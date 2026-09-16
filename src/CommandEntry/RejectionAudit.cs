using System.Text.Json;
using System.Text.Json.Nodes;
using static CommandEntry.RecordJson;

namespace CommandEntry;

internal static class RejectionAudit
{
    internal static JsonObject Record(string logRoot, string tool, JsonObject form, Exception error)
    {
        string id = Guid.NewGuid().ToString();
        var redacted = new JsonArray(); var truncated = new JsonArray();
        string Safe(string field, string text)
        {
            string safe = text.Contains("-----BEGIN ", StringComparison.Ordinal) && text.Contains("PRIVATE KEY-----", StringComparison.Ordinal)
                ? "[REDACTED private key material]" : OutputCapture.RedactLine(text);
            if (safe != text) redacted.Add((JsonNode)field);
            if (OutputCapture.Length(safe) > 1024) { truncated.Add((JsonNode)field); safe = OutputCapture.Slice(safe, 0, 1024); }
            return safe;
        }

        // Only metadata needed to locate a refused call, never arbitrary arguments or payloads.
        var source = tool == "start_operation" ? form["business"] as JsonObject ?? form : form;
        string[] fields = tool == "start_operation"
            ? ["operation", "program", "workdir", "language", "script", "previous_execution"]
            : ["execution_id", "file"];
        var context = new JsonObject();
        foreach (string field in fields)
        {
            if (!source.TryGetPropertyValue(field, out var value)) continue;
            context[field] = value?.GetValueKind() == JsonValueKind.String
                ? JsonValue.Create(Safe(field, value.GetValue<string>()))
                : new JsonObject { ["value_type"] = value?.GetValueKind().ToString() ?? "Null" };
        }
        string reason = error is InvalidRequest ? error.Message.Split(':')[0] : ExecutionRecords.ErrorKind(error);
        var record = new JsonObject
        {
            ["schema_version"] = 1, ["kind"] = "rejected", ["audit_id"] = id, ["ts"] = WindowsProcess.UnixNow,
            ["tool"] = Safe("tool", tool), ["error_kind"] = ExecutionRecords.ErrorKind(error),
            ["reason"] = OutputCapture.Slice(OutputCapture.RedactLine(reason), 0, 80), ["context"] = context,
            ["redacted_fields"] = redacted, ["truncated_fields"] = truncated
        };
        var receipt = new JsonObject { ["audit_id"] = id, ["recorded"] = false };
        try
        {
            string directory = Path.Combine(logRoot, "rejections"), file = Path.Combine(directory, id + ".json");
            Directory.CreateDirectory(directory);
            PublishNew(file, record); // Flush and publish independently of the best-effort shared event log.
            receipt["recorded"] = true; receipt["record_file"] = file;
        }
        catch (Exception failure) when (ExecutionRecords.Handled(failure))
        { receipt["storage_error"] = ExecutionRecords.ErrorKind(failure); }
        error.Data[typeof(RejectionAudit)] = receipt;
        record["audit_recorded"] = receipt["recorded"]?.Copy();
        return record;
    }

    internal static JsonObject? Receipt(Exception error) => error.Data[typeof(RejectionAudit)] as JsonObject;
}
