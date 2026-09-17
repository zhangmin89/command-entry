using System.Text.Json;
using System.Text.Json.Nodes;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace CommandEntry;

internal static class McpHost
{
    internal static async Task Run(string policy, string? binding)
    {
        var execution = new ExecutionServer(policy, binding);
        var options = new McpServerOptions
        {
            ServerInfo = new() { Name = "command-entry-exec-server", Version = "pure-beta.server.3-csharp" },
            ProtocolVersion = "2025-06-18",
            ScopeRequests = false,
            Capabilities = new() { Tools = new() },
            Handlers = new()
            {
                ListToolsHandler = (_, _) => ValueTask.FromResult(new ListToolsResult { Tools = Tools(execution.ProgramKeys) }),
                CallToolHandler = async (context, _) =>
                {
                    try
                    {
                        var form = new JsonObject();
                        if (context.Params?.Arguments is { } arguments)
                            foreach (var pair in arguments) form[pair.Key] = JsonNode.Parse(pair.Value.GetRawText());
                        var value = await execution.Dispatch(context.Params!.Name, form);
                        byte[] json = RecordJson.Packed(value);
                        using var document = JsonDocument.Parse(json);
                        return new CallToolResult { Content = [new TextContentBlock { Text = RecordJson.Utf8.GetString(json) }],
                            StructuredContent = document.RootElement.Clone(), IsError = false };
                    }
                    catch (Exception error) when (ExecutionRecords.Handled(error))
                    {
                        var detail = new JsonObject { ["error"] = ExecutionRecords.ErrorKind(error),
                            ["reason"] = OutputCapture.Slice(OutputCapture.RedactLine(error.Message), 0, 500) };
                        if (RejectionAudit.Receipt(error) is { } audit) detail["rejection_audit"] = audit.Copy();
                        return new CallToolResult { Content = [new TextContentBlock { Text = RecordJson.Utf8.GetString(RecordJson.Packed(detail)) }], IsError = true };
                    }
                }
            }
        };
        await using var server = McpServer.Create(new StdioServerTransport(options), options);
        await server.RunAsync();
    }

    private static IList<Tool> Tools(IEnumerable<string> programs)
    {
        static JsonObject String() => new() { ["type"] = "string" };
        static JsonObject Array() => new() { ["type"] = "array", ["items"] = String() };
        var start = new JsonObject();
        foreach (string name in new[] { "operation", "workdir", "script", "language", "parameters_file", "stdin_file", "encoding", "previous_execution" }) start[name] = String();
        start["program"] = new JsonObject
        {
            ["type"] = "string",
            ["description"] = "Use an exact configured policy key from enum. Do not add or remove .exe, change case, or substitute an executable path. If no matching key is listed, report the missing configuration.",
            ["enum"] = new JsonArray(programs.Select(name => (JsonNode?)JsonValue.Create(name)).ToArray())
        };
        foreach (string name in new[] { "args", "input_paths", "required_tools" }) start[name] = Array();
        start["artifacts"] = new JsonObject { ["type"] = "object" }; start["expected_versions"] = new JsonObject { ["type"] = "object" };
        start["acceptance"] = new JsonObject { ["type"] = "array" };
        start["run_seconds"] = new JsonObject { ["type"] = "integer", ["minimum"] = 1, ["maximum"] = 1800 };
        start["output_quota_bytes"] = new JsonObject { ["type"] = "integer", ["minimum"] = 1024, ["maximum"] = 16777216 };
        var result = new List<Tool>
        {
            Tool("start_operation", "Start one business operation via a detached entry child. Optional run_seconds (integer 1..1800) and output_quota_bytes (integer 1024..16777216 per stream) override policy defaults. The deployment template defaults are 300 seconds and 1048576 bytes. Omit to use the installed policy. Resource changes never start a second copy of running business; query the existing id for its unchanged limits. Records stay at the configured workspace location.", start, ["operation", "program", "workdir"])
        };
        foreach (var (name, description) in new[]
        {
            ("status", "Read the current envelope of one execution from its record directory."),
            ("cancel", "Layered cancel: cancel-request.json first (graceful V2 state machine), hard kill of exact process instances after cancel_grace_seconds."),
            ("wait", "Blocking observation loop over the record directory, bounded by policy wait_budget_seconds. Consecutive observations without progress stop automatic waiting once the policy threshold wait_stop_after_no_progress (deployment template: 12) is reached. All three wait settings are required in policy; no runtime defaults are supplied. Stopping is not confirmation of termination.")
        }) result.Add(Tool(name, description, new() { ["execution_id"] = String() }, ["execution_id"]));
        result.Add(Tool("output", "Paged retrieval of retained redacted output text (offset/count are Unicode characters).",
            new() { ["execution_id"] = String(), ["stream"] = String(), ["offset"] = new JsonObject { ["type"] = "number" }, ["count"] = new JsonObject { ["type"] = "number" } }, ["execution_id"]));
        result.Add(Tool("read_text", "Stateless streaming range read: 1-based line range, strict decoding, complete coverage metadata. Continue with next_start_line. total_lines is null unless total_lines_known is true. Oversized single lines are rejected, never truncated.",
            new() { ["file"] = String(), ["encoding"] = String(), ["start_line"] = new JsonObject { ["type"] = "number" }, ["max_lines"] = new JsonObject { ["type"] = "number" } }, ["file"]));
        return result;
    }

    private static Tool Tool(string name, string description, JsonObject properties, string[] required)
    {
        var schema = new JsonObject { ["type"] = "object", ["properties"] = properties, ["additionalProperties"] = false,
            ["required"] = new JsonArray(required.Select(s => (JsonNode?)JsonValue.Create(s)).ToArray()) };
        using var json = JsonDocument.Parse(RecordJson.Packed(schema));
        return new() { Name = name, Description = description, InputSchema = json.RootElement.Clone() };
    }
}
