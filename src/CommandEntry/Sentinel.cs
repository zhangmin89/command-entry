using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using static CommandEntry.RecordJson;

namespace CommandEntry;

internal static class Sentinel
{
    internal static readonly string[] ShellTools = ["Bash", "shell", "exec_command"];

    internal static (JsonObject Answer, JsonObject Metadata) Handle(string raw)
    {
        var elapsed = Stopwatch.StartNew();
        JsonObject value;
        string route;
        try
        {
            value = JsonNode.Parse(raw) as JsonObject ?? throw new JsonException("event_object_required");
            string? tool = value["tool_name"].Text();
            route = value["hook_event_name"].Text() != "PreToolUse" ? "outside_matcher"
                : string.IsNullOrWhiteSpace(tool) ? "invalid_event_denied"
                : ShellTools.Contains(tool) ? "shell_denied" : "outside_matcher";
        }
        catch (JsonException) { value = new(); route = "invalid_event_denied"; }
        var answer = new JsonObject();
        if (route != "outside_matcher")
            answer["hookSpecificOutput"] = new JsonObject
            {
                ["hookEventName"] = "PreToolUse", ["permissionDecision"] = "deny",
                ["permissionDecisionReason"] = "The shell channel is closed (pure beta). Use the exec server tools: " +
                    "start_operation / status / output / cancel / wait / read_text. " +
                    "Out-of-policy needs follow the exception process, not raw shell. " +
                    "This hook never executes tasks or approves permissions."
            };
        return (answer, new JsonObject
        {
            ["id"] = Guid.NewGuid().ToString(), ["version"] = "pure-beta.hook-sentinel.3", ["route"] = route,
            ["session_id"] = value["session_id"]?.Copy(), ["tool_use_id"] = value["tool_use_id"]?.Copy(),
            ["tool_name"] = value["tool_name"]?.Copy(), ["decision"] = answer.Count == 0 ? "passthrough" : "deny",
            ["elapsed_seconds"] = elapsed.Elapsed.TotalSeconds, ["timestamp"] = WindowsProcess.UnixNow
        });
    }

    internal static JsonObject Run(string raw, string records)
    {
        var (answer, metadata) = Handle(raw);
        try
        {
            Directory.CreateDirectory(records);
            WriteNew(Path.Combine(records, metadata["id"].String() + ".json"), metadata);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            answer["systemMessage"] = "Command entry sentinel record was not persisted; no additional permissions were requested.";
        }
        return answer;
    }
}
