using System.ComponentModel;
using System.Text.Json;
using System.Text.Json.Nodes;
using static CommandEntry.RecordJson;

namespace CommandEntry;

internal static class ExecutionRecords
{
    internal static readonly HashSet<string> Terminal = ["exited", "rejected", "timed_out", "cancelled", "unknown", "tool_error"];
    internal static readonly HashSet<string> ConfirmedTerminal = ["exited", "rejected", "timed_out", "cancelled"];
    internal static bool Handled(Exception error) => error is InvalidRequest or IOException or UnauthorizedAccessException
        or Win32Exception or JsonException or ArgumentException or InvalidOperationException or FormatException or OverflowException or TimeoutException;
    internal static string ErrorKind(Exception error) => error switch
    {
        FileNotFoundException or DirectoryNotFoundException or Win32Exception { NativeErrorCode: 2 or 3 } => "FileNotFoundError",
        InvalidRequest => "Invalid", JsonException or FormatException => "ValueError", IOException or Win32Exception or UnauthorizedAccessException => "OSError",
        _ => error.GetType().Name
    };
    internal static JsonObject Error(Exception error) => error is ExecutionPersistenceFailure failure
        ? (JsonObject)failure.Detail.Copy() : new()
    {
        ["kind"] = ErrorKind(error), ["reason"] = OutputCapture.Slice(OutputCapture.RedactLine(error.Message), 0, 600)
    };

    internal static JsonObject Snapshot(string directory) => Snapshot(directory, WindowsProcess.Observe);

    internal static JsonObject Snapshot(string directory, Func<int, JsonObject> observeOwner)
    {
        string file = Path.Combine(directory, "result.json");
        if (!File.Exists(file)) return new() { ["state"] = "unknown", ["reason"] = "claim_exists_without_readable_state", ["execution_id"] = Path.GetFileName(directory) };
        var state = Read(file);
        if (!Terminal.Contains(state["state"].String()) && state["owner"] is JsonObject owner)
        {
            var current = observeOwner(owner.Int("pid", 0));
            if (owner["creation_time"] is null || !JsonNode.DeepEquals(current["creation_time"], owner["creation_time"]) || !current["alive"].IsTrue())
            {
                // The owner can publish its final state between our read and observation.
                var published = Read(file);
                if (Terminal.Contains(published["state"].String())) return published;
                state["state"] = "unknown"; state["reason"] = "owner_instance_not_confirmed";
            }
            state["owner_observed_now"] = current;
        }
        return state;
    }

    internal static JsonObject Bounded(JsonObject result)
    {
        var view = (JsonObject)result.Copy();
        foreach (string key in new[] { "request", "argv", "bindings", "syntax", "progress_history" }) view.Remove(key);
        if (view["output"] is JsonObject output)
            foreach (var pair in output)
            { pair.Value!.AsObject().Remove("preview_head"); pair.Value.AsObject().Remove("preview_tail"); }
        if (Packed(view).Length <= 12000) return view;
        return new(view.Where(p => new[] { "version", "execution_id", "request_id", "state", "record_dir", "process", "persistence" }.Contains(p.Key))
            .Select(p => KeyValuePair.Create(p.Key, p.Value?.Copy())));
    }

    internal static JsonObject Acceptance(JsonObject request)
    {
        var evidence = new JsonArray();
        foreach (var node in request.ArrayOrEmpty("acceptance"))
        {
            var condition = node.Object();
            string path = BusinessPaths.Resolve(request["artifacts"]![condition["artifact"].String()].String());
            var item = new JsonObject { ["condition"] = condition.Copy(), ["path"] = path, ["matches"] = false };
            try
            {
                if (condition["kind"].Text() == "exists") item["matches"] = File.Exists(path);
                else if (condition["kind"].Text() == "sha256") item["matches"] = FileHash(path) == condition["expected"].Text();
                else
                {
                    JsonNode? value = JsonNode.Parse(File.ReadAllText(path, Utf8));
                    foreach (var key in condition.ArrayOrEmpty("keys"))
                        value = key?.GetValueKind() == JsonValueKind.Number ? value![(int)key.Integer("invalid_key")] : value![key.String()];
                    item["matches"] = JsonNode.DeepEquals(value, condition["expected"]);
                }
            }
            catch (Exception error) when (Handled(error)) { item["error"] = ErrorKind(error); }
            evidence.Add((JsonNode)(item));
        }
        return new() { ["status"] = evidence.Count == 0 ? "unknown" : evidence.All(e => e!["matches"].IsTrue()) ? "confirmed" : "not_fulfilled", ["evidence"] = evidence };
    }

    internal static JsonObject ArtifactObservations(JsonObject request)
    {
        var artifacts = new JsonObject();
        foreach (var pair in request.ObjectOrEmpty("artifacts"))
            try
            {
                var info = new FileInfo(pair.Value.String());
                artifacts[pair.Key] = info.Exists ? new JsonObject { ["size"] = info.Length,
                    ["mtime_ns"] = (info.LastWriteTimeUtc.Ticks - DateTime.UnixEpoch.Ticks) * 100 } : new JsonObject { ["exists"] = false };
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            { artifacts[pair.Key] = new JsonObject { ["unknown"] = true }; }
        return artifacts;
    }

    internal static JsonObject Collect(string directory, JsonObject state)
    {
        var sample = new JsonObject { ["execution_id"] = state["execution_id"]?.Copy(), ["state"] = state["state"]?.Copy(),
            ["observed_at_unix"] = WindowsProcess.UnixNow, ["process"] = state["process"]?.Copy() ?? new JsonObject(),
            ["output"] = state["output"]?.Copy() ?? new JsonObject(), ["output_record_observed_at_unix"] = state["last_observed_unix"]?.Copy() };
        string birthFile = Path.Combine(directory, "business-process.json");
        JsonObject current;
        if (File.Exists(birthFile))
        {
            var birth = Read(birthFile); current = WindowsProcess.Observe(birth.Int("pid", 0));
            bool same = birth["creation_time"] is not null && JsonNode.DeepEquals(birth["creation_time"], current["creation_time"]);
            current["same_instance"] = same;
            if (!same) { current["alive"] = null; current["cpu_seconds"] = null; current["exit_code"] = null; }
        }
        else current = new() { ["alive"] = null, ["cpu_seconds"] = null, ["exit_code"] = null, ["same_instance"] = null };
        sample["business_observation"] = current;
        sample["artifact_observations"] = ArtifactObservations(state.ObjectOrEmpty("request"));
        return sample;
    }

    internal static JsonObject Progress(JsonObject before, JsonObject after)
    {
        var changes = new JsonArray(); var unknown = new JsonArray();
        foreach (var (parent, name) in new[] { ("business_observation", "alive"), ("business_observation", "cpu_seconds"), ("process", "exit_code") })
        {
            var old = before[parent]?[name]; var value = after[parent]?[name]; string key = parent + "." + name;
            if (parent == "process" && before[parent] is JsonObject p && p.ContainsKey(name) && old is null && value is not null) changes.Add((JsonNode)(key));
            else if (old is null || value is null) unknown.Add((JsonNode)(key));
            else if (name == "cpu_seconds" ? value.GetValue<double>() > old.GetValue<double>() : !JsonNode.DeepEquals(old, value)) changes.Add((JsonNode)(key));
        }
        foreach (string stream in new[] { "stdout", "stderr" })
        {
            var old = before["output"]?[stream]?["captured_bytes"]; var value = after["output"]?[stream]?["captured_bytes"];
            if (old is null || value is null) unknown.Add((JsonNode)(stream + "_bytes"));
            else if (value.Integer("captured_bytes") > old.Integer("captured_bytes")) changes.Add((JsonNode)(stream + "_bytes"));
        }
        if (before["artifact_observations"] is not JsonObject previous || after["artifact_observations"] is not JsonObject current)
            unknown.Add((JsonNode)("artifact_observations"));
        else
            foreach (string name in previous.Select(p => p.Key).Union(current.Select(p => p.Key)))
            {
                if (previous[name] is not JsonObject old || current[name] is not JsonObject value || old["unknown"].IsTrue() || value["unknown"].IsTrue()) unknown.Add((JsonNode)("artifact_observations." + name));
                else if (!JsonNode.DeepEquals(old, value)) changes.Add((JsonNode)("artifact_observations." + name));
            }
        return new() { ["progress_confirmed"] = changes.Count != 0, ["changed"] = changes, ["unknown_metrics"] = unknown, ["process_alive"] = after["business_observation"]?["alive"]?.Copy() };
    }
}
