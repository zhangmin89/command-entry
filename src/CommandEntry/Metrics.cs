using System.Text.Json;
using System.Text.Json.Nodes;
using static CommandEntry.RecordJson;

namespace CommandEntry;

internal static class Metrics
{
    internal static JsonObject Collect(string records, string eventsFile, string serve)
    {
        var hooks = new List<JsonObject>();
        int unparsedRecords = 0, unparsedEventLines = 0;
        if (Directory.Exists(records))
            foreach (string path in Directory.GetFiles(records, "*.json").Order())
            {
                try { hooks.Add(Read(path)); }
                catch (Exception error) when (error is JsonException or InvalidRequest or InvalidOperationException)
                { unparsedRecords++; }
            }
        var events = new List<JsonObject>();
        if (File.Exists(eventsFile))
            foreach (string line in File.ReadLines(eventsFile, Utf8))
            {
                try { events.Add(JsonNode.Parse(line).Object()); }
                catch (Exception error) when (error is JsonException or InvalidRequest or InvalidOperationException)
                { unparsedEventLines++; }
            }
        int denied = hooks.Count(value => value["route"].Text() == "shell_denied");
        int invalid = hooks.Count(value => value["route"].Text() == "invalid_event_denied");
        var starts = events.Where(value => value["kind"].Text() == "start_operation").ToArray();
        var rejected = events.Where(value => value["kind"].Text() == "rejected").ToArray();
        var reasons = new JsonObject();
        foreach (var group in rejected.Where(value => value["reason"].Text() is not null).GroupBy(value => value["reason"].String()).OrderBy(group => group.Key))
            reasons[group.Key] = group.Count();
        return new()
        {
            ["complete"] = unparsedRecords == 0 && unparsedEventLines == 0,
            ["hook"] = new JsonObject
            {
                ["unparsed_records"] = unparsedRecords,
                ["total_decisions"] = hooks.Count, ["shell_denied"] = denied, ["invalid_event_denied"] = invalid,
                ["passthrough"] = hooks.Count - denied - invalid,
                ["deny_rate"] = hooks.Count == 0 ? null : Math.Round((double)(denied + invalid) / hooks.Count, 4)
            },
            ["server"] = new JsonObject
            {
                ["unparsed_event_lines"] = unparsedEventLines,
                ["startup_events"] = events.Count(value => value["kind"].Text() == "startup"), ["start_calls"] = starts.Length,
                ["in_flight_dedup_hits"] = starts.Count(value => value["dedup"].IsTrue()),
                ["retries"] = starts.Count(value => value["retry"].IsTrue()), ["rejections_by_reason"] = reasons,
                ["whitelist_misses"] = rejected.Count(value => value["reason"].Text()?.Contains("program_not_configured", StringComparison.Ordinal) == true)
            },
            ["executions"] = new JsonObject { ["serve_inputs"] = Directory.Exists(serve)
                ? Directory.GetDirectories(serve).Count(directory => File.Exists(Path.Combine(directory, "request.json"))) : 0 }
        };
    }
}
