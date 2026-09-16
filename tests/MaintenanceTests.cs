using System.Text.Json.Nodes;
using CommandEntry;
using static CommandEntry.RecordJson;

namespace CommandEntry.Tests;

internal static class MaintenanceTests
{
    [Case]
    private static void SentinelDecisionsAndEnvelopeOnlyRecords()
    {
        using var f = new Fixture();
        foreach (string tool in Sentinel.ShellTools)
            foreach (string command in new[] { "git status", "", "SECRET-COMMAND-CONTENT", "&|%$()`" })
            {
                var (answer, meta) = Sentinel.Handle(new JsonObject { ["hook_event_name"] = "PreToolUse", ["tool_name"] = tool,
                    ["tool_input"] = new JsonObject { ["command"] = command } }.ToJsonString());
                Check.Equal("deny", answer["hookSpecificOutput"]!["permissionDecision"].String());
                Check.Contains("exec server", answer["hookSpecificOutput"]!["permissionDecisionReason"].String()); Check.Equal("shell_denied", meta["route"].String());
                Check.True(!meta.ContainsKey("tool_input"));
            }
        foreach (string tool in new[] { "Read", "Write", "Edit", "Grep", "exec" })
        {
            var (answer, meta) = Sentinel.Handle(new JsonObject { ["hook_event_name"] = "PreToolUse", ["tool_name"] = tool }.ToJsonString());
            Check.Equal(0, answer.Count); Check.Equal("outside_matcher", meta["route"].String());
        }
        Check.Equal(0, Sentinel.Handle("{\"hook_event_name\":\"PostToolUse\",\"tool_name\":\"Bash\"}").Answer.Count);
        foreach (string invalid in new[] { "not json", "null", "[]", "42", "\"text\"" })
        {
            var (answer, meta) = Sentinel.Handle(invalid); Check.Equal("deny", answer["hookSpecificOutput"]!["permissionDecision"].String()); Check.Equal("invalid_event_denied", meta["route"].String());
        }
        string records = f.FilePath("hook-records");
        var run = Fixture.Run(TestRunner.Server, ["sentinel", "--records", records], "{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\"session_id\":\"session-1\",\"tool_input\":{\"command\":\"SECRET-COMMAND-CONTENT\"}}");
        Check.Equal(0, run.Exit); Check.Equal("deny", JsonNode.Parse(run.Out)!["hookSpecificOutput"]!["permissionDecision"].String());
        var files = Directory.GetFiles(records, "*.json"); Check.Equal(1, files.Length); var stored = Read(files[0]);
        Check.Equal("session-1", stored["session_id"].String()); Check.Equal("deny", stored["decision"].String()); Check.True(!File.ReadAllText(files[0]).Contains("SECRET-COMMAND-CONTENT"));
        string blocked = f.Write("not-directory", "retained"); var denied = Sentinel.Run("broken", blocked);
        Check.Equal("deny", denied["hookSpecificOutput"]!["permissionDecision"].String()); Check.Contains("not persisted", denied["systemMessage"].String());
    }

    [Case]
    private static void PolicyValidationBoundsAndNativeBatchGuard()
    {
        using var f = new Fixture(); Check.Equal(0, PolicyMaintenance.Validate(f.Policy).Count);
        foreach (var (key, low, high) in new[] { ("output_quota_bytes", 1024, 16777216), ("read_quota_bytes", 256, 1048576), ("cleanup_seconds", 0, 600),
            ("wait_budget_seconds", 1, 300), ("wait_poll_interval_seconds", 1, 60), ("cancel_grace_seconds", 1, 120), ("cancel_confirm_seconds", 1, 60),
            ("claim_timeout_seconds", 10, 3600), ("start_confirm_seconds", 1, 120), ("wait_stop_after_no_progress", 2, 100) })
        {
            foreach (int value in new[] { low, high }) { var policy = f.Policy.Copy().Object(); policy[key] = value; Check.Equal(0, PolicyMaintenance.Validate(policy).Count); }
            foreach (JsonNode? value in new JsonNode?[] { JsonValue.Create(low - 1), JsonValue.Create(high + 1), JsonValue.Create(true), JsonValue.Create("1"), null })
            { var policy = f.Policy.Copy().Object(); policy[key] = value?.Copy(); Check.True(PolicyMaintenance.Validate(policy).Any(problem => problem.Text() == key + "_out_of_range")); }
        }
        var bad = f.Policy.Copy().Object(); bad["version"] = 1; Check.True(PolicyMaintenance.Validate(bad).Any(item => item.Text() == "version must be 2"));
        string batch = f.Write("native.cmd", "@echo must-not-run"); bad = f.Policy.Copy().Object();
        bad["programs"].Object()["batch"] = new JsonObject { ["kind"] = "native", ["path"] = batch };
        Check.True(PolicyMaintenance.Validate(bad).Any(item => item.Text() == "native_program_must_be_exe:batch"));
        bad = f.Policy.Copy().Object(); bad["read_roots"] = new JsonArray(); Check.Equal(0, PolicyMaintenance.Validate(bad).Count);
        bad["read_roots"] = new JsonArray("@working_roots"); Check.Equal(0, PolicyMaintenance.Validate(bad).Count);
        bad["read_roots"] = new JsonArray("@unknown"); Check.True(PolicyMaintenance.Validate(bad).Any(item => item.Text() == "read_roots_unknown_placeholder"));
        foreach (string operation in new[] { "native", "script", "python_unittest" })
        {
            bad = f.Policy.Copy().Object(); bad["operations"]![operation]!["run_seconds"] = 0;
            Check.True(PolicyMaintenance.Validate(bad).Any(item => item.Text() == "operation_budget_invalid:" + operation));
        }
    }

    [Case]
    private static void InterpreterProgramsAreTheSingleSource()
    {
        using var f = new Fixture();
        var policy = f.Policy.Copy().Object(); policy.Remove("python"); policy.Remove("powershell");
        Check.Equal(0, PolicyMaintenance.Validate(policy).Count);
        var template = Read(Path.Combine(TestRunner.Root, "policy.json"));
        foreach (string name in new[] { "python", "powershell" })
        {
            Check.True(!template.ContainsKey(name) && !f.Policy.ContainsKey(name));
            Check.Json(template["programs"]![name], f.Policy["programs"]![name]);
            var bad = policy.Copy().Object(); bad["programs"]![name]!["path"] = f.FilePath("missing-" + name + ".exe");
            Check.True(PolicyMaintenance.Validate(bad).Any(problem => problem.Text() == "program_path_missing:" + name));
        }
        string file = f.FilePath("programs-only.json"); WriteNew(file, policy);
        var result = Fixture.Run(TestRunner.Server, ["validate-policy", "--policy", file]);
        Check.Equal(0, result.Exit);
    }

    [Case]
    private static void MetricsUseEnvelopesAndCountStartupEventsHonestly()
    {
        using var f = new Fixture(); string records = f.FilePath("metric-hooks"), serve = f.FilePath("metric-serve"); Directory.CreateDirectory(records); Directory.CreateDirectory(Path.Combine(serve, "one"));
        string[] routes = ["shell_denied", "shell_denied", "invalid_event_denied", "outside_matcher"];
        for (int i = 0; i < routes.Length; i++) WriteNew(Path.Combine(records, i + ".json"), new JsonObject { ["route"] = routes[i] });
        File.WriteAllText(Path.Combine(serve, "one", "request.json"), "{}", Utf8);
        string events = f.Write("metrics.jsonl", "{\"kind\":\"startup\"}\n{\"kind\":\"startup\"}\n{\"kind\":\"start_operation\",\"dedup\":true}\n{\"kind\":\"start_operation\",\"retry\":true}\n{\"kind\":\"rejected\",\"reason\":\"program_not_configured\"}\nbroken\n");
        var result = Metrics.Collect(records, events, serve); Check.Equal(2L, result["hook"]!["shell_denied"].Integer("count"));
        Check.Equal(0.75, result["hook"]!["deny_rate"]!.GetValue<double>()); Check.Equal(2L, result["server"]!["startup_events"].Integer("count"));
        Check.Equal(1L, result["server"]!["in_flight_dedup_hits"].Integer("count")); Check.Equal(1L, result["server"]!["retries"].Integer("count"));
        Check.Equal(1L, result["server"]!["whitelist_misses"].Integer("count")); Check.Equal(1L, result["executions"]!["serve_inputs"].Integer("count"));
        Check.True(Metrics.Collect(f.FilePath("missing"), f.FilePath("missing"), f.FilePath("missing"))["hook"]!["deny_rate"] is null);
        var cli = Fixture.Run(TestRunner.Server, ["metrics", "--records", records, "--events", events, "--serve", serve]); Check.Equal(0, cli.Exit); Check.Json(result, JsonNode.Parse(cli.Out));
    }

    [Case]
    private static void BuildBindingIsUsableAndRefusesOverwrite()
    {
        using var f = new Fixture(); string output = f.FilePath("binding.json"), root = Path.GetDirectoryName(TestRunner.Server)!;
        string[] args = ["build-binding", "--runtime-root", root, "--policy", f.PolicyPath, "--output", output];
        var built = Fixture.Run(TestRunner.Server, args); Check.Equal(0, built.Exit); Check.Equal((long)PolicyMaintenance.RuntimeNames(root).Length, JsonNode.Parse(built.Out)!["files"].Integer("count"));
        string[] expected = File.Exists(Path.Combine(root, "CommandEntry.dll"))
            ? ["CommandEntry.exe", "CommandEntry.dll", "CommandEntry.deps.json", "CommandEntry.runtimeconfig.json",
                "CommandEntry.Common.dll", "CommandEntry.Server.dll", "CommandEntry.Owner.dll", "CommandEntry.Worker.dll"]
            : ["CommandEntry.exe"];
        var names = Read(output)["runtime_files"].Array().Select(item => Path.GetFileName(item!["path"].String()));
        Check.Equal(string.Join(",", expected.Order()), string.Join(",", names.Order()));
        byte[] before = File.ReadAllBytes(output); using var bound = new McpClient(f.PolicyPath, output); Check.Equal(6, bound.Rpc("tools/list", new())["tools"].Array().Count);
        var again = Fixture.Run(TestRunner.Server, args); Check.Equal(125, again.Exit); Check.Contains("Refusing to overwrite an existing binding", again.Error); Check.True(File.ReadAllBytes(output).AsSpan().SequenceEqual(before));
    }

    [Case]
    private static void BindingRequiresActualRuntimeEveryMemberAndMatchingHashes()
    {
        using var f = new Fixture(); var original = f.Anchor(); var items = original["runtime_files"].Array();
        var alternatives = new List<JsonArray> { new() };
        for (int i = 0; i < items.Count; i++) alternatives.Add(new JsonArray(items.Where((_, index) => index != i).Select(item => item?.Copy()).ToArray()));
        string foreign = f.FilePath("foreign"); Directory.CreateDirectory(foreign); var copied = new JsonArray();
        foreach (var item in items)
        { string path = Path.Combine(foreign, Path.GetFileName(item!["path"].String())); File.Copy(item["path"].String(), path); copied.Add(new JsonObject { ["path"] = path, ["sha256"] = item["sha256"]?.Copy() }); }
        alternatives.Add(copied);
        if (items.Count > 1) alternatives.Add(new JsonArray(Enumerable.Range(0, items.Count).Select(_ => items[0]?.Copy()).ToArray()));
        int index = 0;
        foreach (var alternative in alternatives)
        {
            var binding = original.Copy().Object(); binding["runtime_files"] = alternative; string path = f.FilePath("invalid-" + index++ + ".json"); WriteNew(path, binding);
            var result = Fixture.Run(TestRunner.Server, ["--policy", f.PolicyPath, "--binding", path]); Check.Equal(125, result.Exit); Check.Contains("runtime_binding_missing_", result.Error);
        }
        for (int i = 0; i < items.Count; i++)
        {
            var tampered = original.Copy().Object(); tampered["runtime_files"]![i]!["sha256"] = new string('0', 64); string tamper = f.FilePath("tampered-" + i + ".json"); WriteNew(tamper, tampered);
            var badHash = Fixture.Run(TestRunner.Server, ["--policy", f.PolicyPath, "--binding", tamper]); Check.Equal(125, badHash.Exit);
            Check.Contains("runtime_changed_since_review_" + Path.GetFileName(items[i]!["path"].String()), badHash.Error);
        }
        foreach (var item in items) item!["path"] = Path.GetDirectoryName(item["path"].String())!.ToUpperInvariant() + "\\.\\" + Path.GetFileName(item["path"].String()).ToUpperInvariant();
        string alias = f.FilePath("alias.json"); WriteNew(alias, original); using var valid = new McpClient(f.PolicyPath, alias); Check.Equal(6, valid.Rpc("tools/list", new())["tools"].Array().Count);
    }

    [Case]
    private static void PolicyTamperingFailsBeforePublication()
    {
        using var f = new Fixture(); var policy = f.Policy.Copy().Object(); policy["read_quota_bytes"] = 4096; Save(f.PolicyPath, policy);
        var rejected = f.Client.Raw("start_operation", f.Form("location")); Check.True(rejected["isError"].IsTrue()); Check.Contains("policy_changed_since_review", rejected.ToJsonString());
        Check.Equal(0, Directory.GetDirectories(f.Serve).Length);
    }

    private static string CopyRuntime(Fixture f, string name)
    {
        string root = f.FilePath(name); Directory.CreateDirectory(root);
        foreach (string path in Directory.GetFiles(Path.GetDirectoryName(TestRunner.Server)!))
            if (Path.GetExtension(path) is ".exe" or ".dll" or ".json") File.Copy(path, Path.Combine(root, Path.GetFileName(path)));
        File.Copy(f.PolicyPath, Path.Combine(root, "policy.json"));
        _ = PolicyMaintenance.BuildBinding(root, Path.Combine(root, "policy.json"), Path.Combine(root, "binding.json"));
        return root;
    }

    [Case]
    private static void MaintenanceCommandsNeedNoPowerShellInterpreter()
    {
        using var f = new Fixture(); string root = CopyRuntime(f, "maintenance-release"), policy = Path.Combine(root, "policy.json");
        var definition = Read(policy);
        definition["programs"].Object().Remove("powershell"); Save(policy, definition);
        var build = Fixture.Run(TestRunner.Server, ["build-binding", "--runtime-root", root, "--policy", policy, "--output", f.FilePath("new-binding.json")]);
        Check.Equal(0, build.Exit); Check.Equal(FileHash(policy), Read(f.FilePath("new-binding.json"))["policy"]!["sha256"].String());
        var update = Fixture.Run(TestRunner.Server, ["update-policy", "--repo-root", root]);
        Check.Equal(0, update.Exit); Check.Equal("verified", JsonNode.Parse(update.Out)!["state"].String());
        string install = PublicationMaintenanceTests.Install(f);
        var preview = Fixture.Run(TestRunner.Server, ["publication-maintenance", "--install-root", install, "--source-root", Path.GetDirectoryName(TestRunner.Server)!]);
        Check.Equal(0, preview.Exit); Check.True(!JsonNode.Parse(preview.Out)!["apply"].IsTrue());
        Check.True(!Directory.Exists(Path.Combine(install, "maintenance")));
    }

    [Case]
    private static void PolicyUpdateBacksUpRepinsAndRejectsInvalidCandidate()
    {
        using var f = new Fixture(); string root = CopyRuntime(f, "release"); string policy = Path.Combine(root, "policy.json"), binding = Path.Combine(root, "binding.json");
        byte[] oldPolicy = File.ReadAllBytes(policy), oldBinding = File.ReadAllBytes(binding);
        var candidate = f.Policy.Copy().Object(); candidate["read_quota_bytes"] = 4096; string path = f.FilePath("candidate.json"); WriteNew(path, candidate);
        var update = Fixture.Run(TestRunner.Server, ["update-policy", "--repo-root", root, "--policy", path]); Check.Equal(0, update.Exit);
        var anchor = Read(binding); Check.Equal(FileHash(policy), anchor["policy"]!["sha256"].String());
        string[] backups = Directory.GetDirectories(Path.Combine(root, "policy-backups")); Check.Equal(1, backups.Length);
        Check.True(File.ReadAllBytes(Path.Combine(backups[0], "policy.json")).AsSpan().SequenceEqual(oldPolicy));
        Check.True(File.ReadAllBytes(Path.Combine(backups[0], "binding.json")).AsSpan().SequenceEqual(oldBinding));
        using (var valid = new McpClient(policy, binding, Path.Combine(root, "CommandEntry.exe"))) Check.Equal(6, valid.Rpc("tools/list", new())["tools"].Array().Count);
        string policyHash = FileHash(policy), bindingHash = FileHash(binding); candidate["read_quota_bytes"] = 0; Save(path, candidate);
        var invalid = Fixture.Run(TestRunner.Server, ["update-policy", "--repo-root", root, "--policy", path]); Check.Equal(125, invalid.Exit); Check.Contains("validation failed", invalid.Error);
        Check.Equal(policyHash, FileHash(policy)); Check.Equal(bindingHash, FileHash(binding)); Check.Equal(1, Directory.GetDirectories(Path.Combine(root, "policy-backups")).Length);
        var same = Fixture.Run(TestRunner.Server, ["update-policy", "--repo-root", root, "--policy", policy]); Check.Equal(0, same.Exit); Check.Equal(policyHash, FileHash(policy)); Check.Equal(bindingHash, FileHash(binding));
    }

    [Case]
    private static void PolicyUpdateRollsBackPairOnBindingFailure()
    {
        using var f = new Fixture(); string root = CopyRuntime(f, "rollback"); string policy = Path.Combine(root, "policy.json"), binding = Path.Combine(root, "binding.json");
        string originalPolicy = FileHash(policy), originalBinding = FileHash(binding);
        var candidate = f.Policy.Copy().Object(); candidate["read_quota_bytes"] = 4096; string path = f.FilePath("candidate.json"); WriteNew(path, candidate);
        // Deny read access to the test-owned runtime while re-pinning, after candidate validation.
        using (var exclusive = new FileStream(Path.Combine(root, "CommandEntry.exe"), FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            var result = Fixture.Run(TestRunner.Server, ["update-policy", "--repo-root", root, "--policy", path]); Check.Equal(125, result.Exit); Check.Contains("old policy+binding pair was restored", result.Error);
            Check.Equal(originalPolicy, FileHash(policy)); Check.Equal(originalBinding, FileHash(binding));
        }
        using var restored = new McpClient(policy, binding, Path.Combine(root, "CommandEntry.exe")); Check.Equal(6, restored.Rpc("tools/list", new())["tools"].Array().Count);
    }

    [Case]
    private static void PolicyMaintenanceNeedsNoPythonInterpreter()
    {
        using var f = new Fixture(); string root = CopyRuntime(f, "no-python"); string policy = Path.Combine(root, "policy.json");
        var definition = Read(policy); definition["programs"].Object().Remove("python"); Save(policy, definition);
        var update = Fixture.Run(TestRunner.Server, ["update-policy", "--repo-root", root]); Check.Equal(0, update.Exit);
        var added = Fixture.Run(TestRunner.Server, ["update-policy", "--repo-root", root, "--add-program", "another", "--program-path", TestRunner.ProbeExe, "--kind", "native"]);
        Check.Equal(0, added.Exit); Check.Equal(TestRunner.ProbeExe, Read(policy)["programs"]!["another"]!["path"].String());
        string hash = FileHash(policy), bindingHash = FileHash(Path.Combine(root, "binding.json"));
        var missing = Fixture.Run(TestRunner.Server, ["update-policy", "--repo-root", root, "--add-program", "missing", "--program-path", f.FilePath("missing.exe")]);
        Check.Equal(125, missing.Exit); Check.Equal(hash, FileHash(policy)); Check.Equal(bindingHash, FileHash(Path.Combine(root, "binding.json")));
    }
}
