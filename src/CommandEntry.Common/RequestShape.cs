using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using static CommandEntry.RecordJson;

namespace CommandEntry;

internal static class JsonFields
{
    internal static JsonNode Copy(this JsonNode value) => value.DeepClone();
    internal static string String(this JsonNode? value, string reason = "string_required")
    {
        Require(value?.GetValueKind() == JsonValueKind.String, reason);
        return value!.GetValue<string>();
    }
    internal static string? Text(this JsonNode? value) => value?.GetValueKind() == JsonValueKind.String ? value.GetValue<string>() : null;
    internal static bool IsTrue(this JsonNode? value) => value?.GetValueKind() == JsonValueKind.True;
    internal static long Integer(this JsonNode? value, string reason)
    {
        string? raw = value?.GetValueKind() == JsonValueKind.Number ? value.ToJsonString() : null;
        Require(raw is not null && raw.IndexOfAny(['.', 'e', 'E']) < 0, reason);
        Require(long.TryParse(raw, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out long result), reason);
        return result;
    }
    internal static int Int(this JsonObject obj, string key, int defaultValue)
    {
        if (!obj.ContainsKey(key)) return defaultValue;
        long value = obj[key].Integer("invalid_" + key);
        Require(value >= int.MinValue && value <= int.MaxValue, "invalid_" + key);
        return (int)value;
    }
    internal static JsonObject Object(this JsonNode? value, string reason = "object_required") =>
        value as JsonObject ?? throw new InvalidRequest(reason);
    internal static JsonArray Array(this JsonNode? value, string reason = "array_required") =>
        value as JsonArray ?? throw new InvalidRequest(reason);
    internal static JsonArray ArrayOrEmpty(this JsonObject value, string name) =>
        value.ContainsKey(name) ? value[name].Array(name + "_must_be_array") : new();
    internal static JsonObject ObjectOrEmpty(this JsonObject value, string name) =>
        value.ContainsKey(name) ? value[name].Object(name + "_object_required") : new();
    internal static void Known(this JsonObject value, IEnumerable<string> names, string reason = "unknown_form_fields")
    {
        var allowed = names.ToHashSet(StringComparer.Ordinal);
        Require(value.All(pair => allowed.Contains(pair.Key)), reason);
    }
    internal static bool IsUuid(string? value) => Guid.TryParseExact(value, "D", out var id) && id.ToString() == value;
}

internal static class RequestShape
{
    internal static readonly string[] ExecutionKeys = ["run_seconds", "output_quota_bytes"];
    internal static readonly string[] StartFields = ["operation", "program", "language", "script", "parameters_file", "args",
        "stdin_file", "input_paths", "required_tools", "encoding", "artifacts", "acceptance", "expected_versions",
        "workdir", "previous_execution", "run_seconds", "output_quota_bytes"];

    internal static JsonObject Options(JsonObject request, JsonObject policy)
    {
        var definition = policy["operations"]?[request["operation"].String()] as JsonObject;
        Require(definition?.ContainsKey("run_seconds") == true, "approved_run_budget_missing");
        Require(policy.ContainsKey("output_quota_bytes"), "approved_output_quota_missing");
        var defaults = new JsonObject { ["run_seconds"] = definition!["run_seconds"]?.Copy(),
            ["output_quota_bytes"] = policy["output_quota_bytes"]?.Copy() };
        CheckOptions(defaults);
        CheckOptions(request);
        foreach (string key in ExecutionKeys)
            if (request.ContainsKey(key)) defaults[key] = request[key]?.Copy();
        return defaults;
    }

    private static void CheckOptions(JsonObject request)
    {
        foreach (var (key, low, high) in new[] { ("run_seconds", 1, 1800), ("output_quota_bytes", 1024, 16777216) })
        {
            if (!request.ContainsKey(key)) continue;
            string reason = $"{key}_range_{low}_{high}";
            long value = request[key].Integer(reason);
            Require(value >= low && value <= high, reason);
        }
    }

    internal static string Absolute(JsonNode? value)
    {
        string path = value.String("invalid_path");
        Require(path.Length != 0 && !path.Contains('\0'), "invalid_path");
        Require(Path.IsPathFullyQualified(path), "absolute_windows_path_required");
        return Path.GetFullPath(path);
    }

    internal static JsonObject Shape(JsonObject source)
    {
        var req = (JsonObject)source.Copy();
        req.Known(["task_ref", "step_ref", "attempt", "previous_request", "operation", "cwd", "program", "language", "script",
            "args", "parameters_file", "stdin_file", "input_paths", "required_tools", "encoding", "file", "start_line",
            "line_count", "execution_id", "stream", "offset", "count", "artifacts", "acceptance", "expected_versions",
            "wait_receipt", "run_seconds", "output_quota_bytes"], "unknown_request_fields");
        foreach (string key in new[] { "task_ref", "step_ref" })
            Require(req[key].Text() is { Length: > 0 and <= 160 }, key + "_required");
        string operation = req["operation"].String("unsupported_operation");
        Require(operation is "location" or "read_text" or "native" or "script" or "python_unittest" or "status" or "output" or "cancel", "unsupported_operation");
        if (ExecutionKeys.Any(req.ContainsKey))
        {
            Require(operation is "native" or "script" or "python_unittest", "execution_options_require_execution_operation");
            CheckOptions(req);
        }
        req["cwd"] = Absolute(req["cwd"]);
        if (!req.ContainsKey("attempt")) req["attempt"] = 0;
        long attempt = req["attempt"].Integer("invalid_attempt");
        Require(attempt >= 0, "invalid_attempt");
        if (attempt > 0) Require(JsonFields.IsUuid(req["previous_request"].Text()), "previous_request_required");
        else Require(!req.ContainsKey("previous_request"), "initial_attempt_has_no_previous_request");
        Require(req.ArrayOrEmpty("args").All(v => v.Text() is { } a && !a.Contains('\0')), "args_must_be_strings");
        if (req.ContainsKey("stdin_file"))
            Require(operation is "native" or "script" or "python_unittest", "stdin_file_requires_execution_operation");
        foreach (string key in new[] { "script", "parameters_file", "file", "stdin_file" })
            if (req.ContainsKey(key)) req[key] = Absolute(req[key]);
        foreach (string key in new[] { "input_paths", "required_tools" })
            if (req.ContainsKey(key)) req[key] = new JsonArray(req.ArrayOrEmpty(key).Select(v => (JsonNode?)JsonValue.Create(Absolute(v))).ToArray());
        Require(!req.ContainsKey("encoding") || req["encoding"].Text() is "utf-8" or "gbk" or "utf-16-le", "unsupported_encoding");
        if (operation is "native" or "script" or "python_unittest")
            _ = req["program"].String("program_identifier_required");
        if (operation == "script")
            Require(req["language"].Text() is "python" or "powershell" or "javascript" or "bash" && req.ContainsKey("script"), "script_language_and_reference_required");
        if (operation == "read_text")
        {
            Require(req.ContainsKey("file"), "file_required");
            Require(req.Int("start_line", 1) >= 1, "invalid_start_line");
            Require(req.Int("line_count", 100) is >= 1 and <= 1000, "line_count_range_1_1000");
        }
        if (operation is "status" or "output" or "cancel")
            Require(JsonFields.IsUuid(req["execution_id"].Text()), "execution_id_required");
        if (req.ContainsKey("wait_receipt"))
        {
            Require(operation == "status", "wait_receipt_only_for_status");
            Require(req["wait_receipt"].Text() == "host-" + req["execution_id"].String() + ".json", "wait_receipt_must_match_execution");
        }
        if (operation == "output")
        {
            Require(!req.ContainsKey("stream") || req["stream"].Text() is "stdout" or "stderr", "invalid_stream");
            Require(req.Int("offset", 0) >= 0, "invalid_offset");
            Require(req.Int("count", 2048) is >= 1 and <= 4096, "output_count_range_1_4096");
        }
        var artifacts = req.ObjectOrEmpty("artifacts");
        foreach (string key in artifacts.Select(p => p.Key).ToArray())
        {
            Require(key.Length > 0, "artifact_name_required");
            artifacts[key] = Absolute(artifacts[key]);
        }
        foreach (var item in req.ArrayOrEmpty("acceptance"))
        {
            var condition = item.Object("acceptance_must_reference_declared_artifact");
            Require(condition["artifact"].Text() is { } name && artifacts.ContainsKey(name), "acceptance_must_reference_declared_artifact");
            Require(condition["kind"].Text() is "exists" or "json_equals" or "sha256", "unsupported_acceptance");
            if (condition["kind"].Text() != "exists") Require(condition.ContainsKey("expected"), "expected_acceptance_value_required");
        }
        var versions = new JsonObject();
        foreach (var pair in req.ObjectOrEmpty("expected_versions"))
        {
            string? hash = pair.Value.Text();
            Require(hash is { Length: 64 } && hash.All(c => "0123456789abcdef".Contains(c)), "invalid_content_digest");
            versions[Absolute(JsonValue.Create(pair.Key))] = hash;
        }
        req["expected_versions"] = versions;
        req["request_id"] = RequestId(req["task_ref"].String(), req["step_ref"].String(), attempt);
        req["logical_id"] = LogicalId(req["task_ref"].String(), req["step_ref"].String());
        req["version"] = RecordJson.Version;
        return req;
    }
}
