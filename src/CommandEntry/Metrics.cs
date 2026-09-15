using System.Text.Json;
using System.Text.Json.Nodes;
using static CommandEntry.RecordJson;

namespace CommandEntry;

internal static class Metrics
{
    internal static JsonObject Collect(string records, string eventsFile, string serve)
    {
        var hooks = Directory.Exists(records) ? Directory.GetFiles(records, "*.json").Order().Select(Read).ToArray() : [];
        var events = new List<JsonObject>();
        if (File.Exists(eventsFile))
            foreach (string line in File.ReadLines(eventsFile, Utf8))
            {
                try { events.Add(JsonNode.Parse(line).Object()); }
                catch (JsonException) { /* Preserve the metrics reader's treatment of incomplete log lines. */ }
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
            ["hook"] = new JsonObject
            {
                ["total_decisions"] = hooks.Length, ["shell_denied"] = denied, ["invalid_event_denied"] = invalid,
                ["passthrough"] = hooks.Length - denied - invalid,
                ["deny_rate"] = hooks.Length == 0 ? null : Math.Round((double)(denied + invalid) / hooks.Length, 4)
            },
            ["server"] = new JsonObject
            {
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
