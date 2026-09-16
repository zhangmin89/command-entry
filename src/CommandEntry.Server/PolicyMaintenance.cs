using System.Text.Json;
using System.Text.Json.Nodes;
using static CommandEntry.RecordJson;

namespace CommandEntry;

internal static class PolicyMaintenance
{
    internal static JsonArray Validate(JsonObject policy)
    {
        var problems = new JsonArray();
        void Need(bool condition, string reason) { if (!condition) problems.Add((JsonNode)reason); }
        bool IntegerIn(JsonNode? value, int low, int high)
        {
            try { long number = value.Integer("integer_required"); return number >= low && number <= high; }
            catch (InvalidRequest) { return false; }
        }
        Need(policy["version"]?.ToJsonString() == "2", "version must be 2");
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
            ("wait_budget_seconds", 1, 300), ("wait_poll_interval_seconds", 1, 60), ("cancel_grace_seconds", 1, 120),
            ("cancel_confirm_seconds", 1, 60), ("claim_timeout_seconds", 10, 3600), ("start_confirm_seconds", 1, 120),
            ("wait_stop_after_no_progress", 2, 100)
        }) Need(!policy.ContainsKey(key) || IntegerIn(policy[key], low, high), key + "_out_of_range");
        Need(!policy.ContainsKey("require_orphan_guarantee") || policy["require_orphan_guarantee"]?.GetValueKind() is JsonValueKind.True or JsonValueKind.False,
            "require_orphan_guarantee_must_be_bool");
        var roots = policy["read_roots"];
        Need(roots is null || roots is JsonArray paths && paths.All(path => path.Text() is not null), "read_roots_invalid");
        if (roots is JsonArray list)
            Need(list.All(path => path.Text() is not { } text || !text.StartsWith('@') || text == "@working_roots"), "read_roots_unknown_placeholder");
        return problems;
    }

    internal static string[] RuntimeNames(string root) => RuntimeNames(File.Exists(Path.Combine(root, "CommandEntry.dll")));

    internal static string[] RuntimeNames(bool managed) => managed
        ? ["CommandEntry.exe", "CommandEntry.dll", "CommandEntry.deps.json", "CommandEntry.runtimeconfig.json",
            "CommandEntry.Common.dll", "CommandEntry.Server.dll", "CommandEntry.Owner.dll", "CommandEntry.Worker.dll"]
        : ["CommandEntry.exe"];

    internal static JsonObject BuildBinding(string runtimeRoot, string policyPath, string outputPath)
    {
        string root = BusinessPaths.Resolve(runtimeRoot, "directory"), policy = BusinessPaths.Resolve(policyPath, "file");
        string output = RequestShape.Absolute(JsonValue.Create(outputPath));
        Require(!File.Exists(output) && !Directory.Exists(output), "Refusing to overwrite an existing binding: " + output);
        Require(Directory.Exists(Path.GetDirectoryName(output)), "The output parent directory must already exist.");
        using var locks = new FileBindings();
        locks.Add(policy);
        var runtime = new JsonArray();
        foreach (string name in RuntimeNames(root))
        {
            string path = BusinessPaths.Resolve(Path.Combine(root, name), "file"); locks.Add(path);
            runtime.Add((JsonNode)new JsonObject { ["path"] = path, ["sha256"] = locks.Bindings[path]?.Copy() });
        }
        var binding = new JsonObject
        {
            ["schema_version"] = 2, ["phase"] = File.Exists(Path.Combine(root, "CommandEntry.dll")) ? "csharp_managed" : "csharp_native_aot",
            ["policy"] = new JsonObject { ["path"] = policy, ["sha256"] = locks.Bindings[policy]?.Copy() }, ["runtime_files"] = runtime
        };
        WriteNew(output, binding);
        Require(JsonNode.DeepEquals(Read(output), binding), "Written binding did not pass artifact validation.");
        return new() { ["written"] = output, ["files"] = runtime.Count, ["policy_sha256"] = locks.Bindings[policy]?.Copy() };
    }

    internal static JsonObject Update(string repoRoot, string? policyPath, string? addProgram, string? programPath, string kind = "native")
    {
        string root = BusinessPaths.Resolve(repoRoot, "directory");
        Require(File.Exists(Path.Combine(root, "CommandEntry.exe")), "RepoRoot does not contain CommandEntry.exe.");
        string live = BusinessPaths.Resolve(Path.Combine(root, "policy.json"), "file"), binding = Path.Combine(root, "binding.json");
        string stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N")[..6];
        byte[] candidate;
        if (addProgram is not null)
        {
            Require(programPath is not null, "--program-path is required with --add-program.");
            string program = BusinessPaths.Resolve(programPath!, "file");
            Require(kind is "native" or "python" or "powershell" or "javascript", "unsupported_program_kind");
            var definition = Read(live);
            definition["programs"].Object()[addProgram] = new JsonObject { ["kind"] = kind, ["path"] = program };
            candidate = Packed(definition);
        }
        else candidate = File.ReadAllBytes(policyPath is null ? live : BusinessPaths.Resolve(policyPath, "file"));
        JsonArray problems = Validate(JsonNode.Parse(Utf8.GetString(candidate).TrimStart('\ufeff')).Object());
        Require(problems.Count == 0, "Candidate validation failed; nothing was deployed: " + Utf8.GetString(Packed(problems)));
        string backup = Path.Combine(root, "policy-backups", stamp);
        Directory.CreateDirectory(backup);
        File.Copy(live, Path.Combine(backup, "policy.json"), overwrite: false);
        bool hadBinding = File.Exists(binding);
        if (hadBinding) File.Copy(binding, Path.Combine(backup, "binding.json"), overwrite: false);
        string nextBinding = Path.Combine(root, "binding-candidate-" + stamp + ".json");
        try
        {
            if (!File.ReadAllBytes(live).AsSpan().SequenceEqual(candidate)) File.WriteAllBytes(live, candidate);
            _ = BuildBinding(root, live, nextBinding);
            File.Move(nextBinding, binding, overwrite: true);
        }
        catch (Exception error) when (ExecutionRecords.Handled(error))
        {
            File.Copy(Path.Combine(backup, "policy.json"), live, overwrite: true);
            if (hadBinding) File.Copy(Path.Combine(backup, "binding.json"), binding, overwrite: true);
            throw new IOException("Mid-flight failure; the old policy+binding pair was restored from " + backup, error);
        }
        return new() { ["state"] = "verified", ["backup"] = backup, ["binding"] = binding,
            ["policy_sha256"] = FileHash(live), ["note"] = "Restart the exec server for the new policy to take effect." };
    }
}
