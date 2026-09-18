using System.Text.Json;
using System.Text.Json.Nodes;
using static CommandEntry.RecordJson;

namespace CommandEntry;

internal static class PolicyValidator
{
    private static bool IntegerIn(JsonNode? value, int low, int high)
    {
        try { long number = value.Integer("integer_required"); return number >= low && number <= high; }
        catch (InvalidRequest) { return false; }
    }

    internal static JsonArray ValidateWaitSettings(JsonObject policy)
    {
        var problems = new JsonArray();
        foreach (var (key, low, high) in new[] { ("wait_budget_seconds", 1, 300), ("wait_poll_interval_seconds", 1, 60), ("wait_stop_after_no_progress", 2, 100) })
        {
            if (!policy.ContainsKey(key)) problems.Add((JsonNode)(key + "_required"));
            else if (!IntegerIn(policy[key], low, high)) problems.Add((JsonNode)(key + "_out_of_range"));
        }
        return problems;
    }

    internal static JsonArray Validate(JsonObject policy)
    {
        var problems = ValidateWaitSettings(policy);
        void Need(bool condition, string reason) { if (!condition) problems.Add((JsonNode)reason); }
        Need(policy["version"]?.ToJsonString() == "3", "version must be 3");
        foreach (string key in new[] { "record_root", "serve_root", "working_roots" })
            Need(key == "working_roots" ? policy[key] is JsonArray { Count: > 0 } : policy[key].Text() is not null, key + "_required");
        Need(policy["programs"] is JsonObject { Count: > 0 }, "programs_required");
        if (policy["programs"] is JsonObject programs)
            foreach (var (name, item) in programs)
            {
                var definition = item as JsonObject;
                string? kind = definition?["kind"].Text(), path = definition?["path"].Text();
                Need(definition is not null && kind is "native" or "python" or "powershell" or "javascript" && path is not null, "program_invalid:" + name);
                Need(path is not null && File.Exists(path), "program_path_missing:" + name);
                if (kind == "native" && path is not null) Need(path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase), "native_program_must_be_exe:" + name);
            }
        foreach (string name in new[] { "native", "script", "python_unittest" })
        {
            var definition = (policy["operations"] as JsonObject)?[name] as JsonObject;
            Need(IntegerIn(definition?["run_seconds"], 1, 1800), "operation_budget_invalid:" + name);
            Need(definition?["wait_category"].Text() is "long_task" or "process_readiness", "wait_category_invalid:" + name);
        }
        foreach (var (key, low, high) in new[]
        {
            ("output_quota_bytes", 1024, 16777216), ("read_quota_bytes", 256, 1048576), ("cleanup_seconds", 0, 600),
            ("cancel_grace_seconds", 1, 120), ("cancel_confirm_seconds", 1, 60),
            ("claim_timeout_seconds", 10, 3600), ("start_confirm_seconds", 1, 120)
        }) Need(!policy.ContainsKey(key) || IntegerIn(policy[key], low, high), key + "_out_of_range");
        Need(!policy.ContainsKey("require_orphan_guarantee") || policy["require_orphan_guarantee"]?.GetValueKind() is JsonValueKind.True or JsonValueKind.False,
            "require_orphan_guarantee_must_be_bool");
        var roots = policy["read_roots"];
        Need(roots is null || roots is JsonArray paths && paths.All(path => path.Text() is not null), "read_roots_invalid");
        if (roots is JsonArray list)
            Need(list.All(path => path.Text() is not { } text || !text.StartsWith('@') || text == "@working_roots"), "read_roots_unknown_placeholder");
        return problems;
    }
}
