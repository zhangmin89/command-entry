using System.Diagnostics;
using System.Text.Json.Nodes;
using CommandEntry;
using static CommandEntry.RecordJson;

namespace CommandEntry.Tests;

[Trait("Suite", "Regression")]
public sealed class AuditBoundaryTests
{
    [Theory, InlineData("request"), InlineData("policy"), InlineData("missing_proof"), Trait("Category", "Integration")]
    public async Task OwnerRejectsChangedPublicationBeforeCreatingRecords(string changed)
    {
        using var f = new Fixture();
        var business = f.Form("text", "reviewed"); business.Remove("workdir");
        business["cwd"] = f.DirectoryPath; business["task_ref"] = "publication-proof"; business["step_ref"] = changed;
        var request = RequestShape.Shape(business);
        string id = ExecutionId(request["request_id"].String()), directory = f.FilePath("publication");
        Directory.CreateDirectory(directory);
        var envelope = new JsonObject { ["business"] = business, ["fingerprint"] = RequestDigest(request) };
        string requestPath = Path.Combine(directory, "request.json"), policyPath = Path.Combine(directory, "policy.json");
        WriteNew(requestPath, envelope); WriteNew(policyPath, f.Policy);
        string requestHash = FileHash(requestPath), policyHash = FileHash(policyPath);
        if (changed == "request")
        {
            business["args"] = new JsonArray("probe", "text", "tampered");
            envelope["fingerprint"] = RequestDigest(RequestShape.Shape(business)); Save(requestPath, envelope);
        }
        else if (changed == "policy")
        {
            var policy = (JsonObject)f.Policy.Copy(); policy["record_root"] = f.FilePath("redirected-records"); Save(policyPath, policy);
        }
        var info = WindowsProcess.StartInfo(TestEnvironment.Server, [], TestEnvironment.Root);
        info.Environment["COMMAND_ENTRY_OWNER_INPUT"] = directory;
        if (changed != "missing_proof") info.Environment["COMMAND_ENTRY_OWNER_REQUEST_SHA256"] = requestHash;
        info.Environment["COMMAND_ENTRY_OWNER_POLICY_SHA256"] = policyHash;
        using var process = Process.Start(info)!;
        var stdout = process.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken); var stderr = process.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken); process.StandardInput.Close();
        await process.WaitForExitAsync(TestContext.Current.CancellationToken).WaitAsync(TimeSpan.FromSeconds(15), TestContext.Current.CancellationToken);
        _ = await stdout; _ = await stderr;
        Assert.Equal(125, process.ExitCode);
        Assert.Contains(changed == "missing_proof" ? "publication_proof_required" : "publication_" + changed + "_changed", Read(Path.Combine(directory, "serve-error.json"))["error"]!["reason"].String());
        Assert.False(Directory.Exists(Path.Combine(f.DirectoryPath, ".codex-command-records", id)));
        Assert.False(Directory.Exists(f.FilePath("redirected-records")));
    }

    [Theory, InlineData("input_paths"), InlineData("required_tools"), InlineData("stdin_file"), InlineData("artifacts"), InlineData("encoding"), InlineData("script"), Trait("Category", "Integration")]
    public void EquivalentFormsShareRunningIdentity(string field)
    {
        using var f = new Fixture(); string file = f.Write("input.txt", "data");
        var first = f.Form("sleep", "2500");
        if (field == "script") first = f.Script(f.Write("work.py", "import time\ntime.sleep(2.5)\nprint('once')\n"), "python");
        else if (field is "input_paths" or "required_tools") first[field] = new JsonArray(file);
        else if (field == "stdin_file") first[field] = file;
        else if (field == "artifacts") first[field] = new JsonObject { ["out"] = f.FilePath("future.txt") };
        var second = (JsonObject)first.Copy();
        string Alias(string path) => Path.Combine(Path.GetDirectoryName(path)!, ".", Path.GetFileName(path)).ToUpperInvariant();
        if (field == "encoding") second[field] = "utf-8";
        else if (field is "input_paths" or "required_tools") second[field] = new JsonArray(Alias(file));
        else if (field == "artifacts") second[field]!["out"] = Alias(first[field]!["out"].String());
        else second[field] = Alias(first[field].String());
        string id = f.Start(first)["execution_id"].String();
        using var other = new McpClient(f.PolicyPath);
        var duplicate = other.Call("start_operation", second);
        Assert.Equal(id, duplicate["execution_id"].String()); Assert.True(duplicate["in_flight_dedup"].IsTrue());
        Assert.Equal("exited", f.Terminal(id)["state"].String());
    }

    [Theory, InlineData("unknown"), InlineData("tool_error"), Trait("Category", "Integration")]
    public void WaitDoesNotClaimUnconfirmedProcessesAreTerminal(string state)
    {
        using var f = new Fixture(); string id = Guid.NewGuid().ToString();
        string publication = Path.Combine(f.Serve, id), record = Path.Combine(f.DirectoryPath, ".codex-command-records", id);
        Directory.CreateDirectory(publication); Directory.CreateDirectory(record);
        WriteNew(Path.Combine(publication, "request.json"), new JsonObject { ["business"] = new JsonObject { ["cwd"] = f.DirectoryPath } });
        WriteNew(Path.Combine(record, "result.json"), new JsonObject { ["state"] = state, ["execution_id"] = id });
        var result = f.Client.Call("wait", new JsonObject { ["execution_id"] = id });
        Assert.Equal(state, result["state"].String()); Assert.Equal("unconfirmed", result["wait_outcome"].String());
        Assert.Contains("cancel", result["note"].String()); Assert.False(File.Exists(Path.Combine(record, "wait-state.json")));
    }

    [Fact, Trait("Category", "Integration")]
    public void BusyEventMutexDoesNotHoldBusinessCallsIndefinitely()
    {
        using var f = new Fixture(); string file = f.Write("read.txt", "available\n");
        string root = BusinessPaths.Resolve(f.Policy["log_root"].String());
        using var held = new ManualResetEventSlim(); using var release = new ManualResetEventSlim();
        var holder = new Thread(() =>
        {
            using var mutex = new Mutex(false, @"Global\CommandEntry.ServerEvents." + Hash(Utf8.GetBytes(root.ToUpperInvariant())));
            mutex.WaitOne(); held.Set();
            try { release.Wait(TimeSpan.FromSeconds(8)); } finally { mutex.ReleaseMutex(); }
        });
        holder.Start(); Assert.True(held.Wait(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken));
        var elapsed = Stopwatch.StartNew();
        try
        {
            var result = f.Client.Call("read_text", new JsonObject { ["file"] = file });
            Assert.Equal("available\n", result["text"].String());
            Assert.True(elapsed.Elapsed < TimeSpan.FromSeconds(6), "Event logging blocked the call for " + elapsed.Elapsed);
        }
        finally { release.Set(); Assert.True(holder.Join(10000)); }
        Assert.Equal("available\n", f.Client.Call("read_text", new JsonObject { ["file"] = file })["text"].String());
    }

    [Fact, Trait("Category", "Integration")]
    public void OpenedReadHandleMustStillBelongToAllowedRoot()
    {
        using var f = new Fixture(); string root = f.FilePath("allowed"); Directory.CreateDirectory(root);
        string inside = Path.Combine(root, "inside.txt"); File.WriteAllText(inside, "allowed", Utf8);
        string outside = f.Write("outside.txt", "outside");
        Assert.True(BusinessPaths.Within(BusinessPaths.Resolve(inside, "file"), root));
        // Model the open after a path swap: admission saw inside, but this is the actual read handle.
        using var redirected = File.OpenRead(outside);
        TestAssert.Throws<InvalidRequest>(() => TextRangeReader.CheckOpenedPath(redirected, [root]), "file_outside_read_roots");
        Assert.Equal(0, redirected.Position);
        using var accepted = File.OpenRead(inside);
        Assert.Equal(inside, TextRangeReader.CheckOpenedPath(accepted, [root]));
        Assert.Equal(0, accepted.Position);
        var policy = (JsonObject)f.Policy.Copy(); policy["read_roots"] = new JsonArray(root);
        Assert.Equal("allowed", TextRangeReader.Read(new JsonObject { ["file"] = inside }, policy)["text"].String());
        TestAssert.Throws<InvalidRequest>(() => TextRangeReader.Read(new JsonObject { ["file"] = outside }, policy), "file_outside_read_roots");
    }

    [Fact, Trait("Category", "Integration")]
    public void EquivalentIdentityNormalizesPathsButPreservesArgumentsAndArtifactNames()
    {
        using var f = new Fixture(); string file = f.Write("source.txt", "input"); string alias = Path.Combine(f.DirectoryPath, ".", "source.txt").ToUpperInvariant();
        var first = f.Form("text", "CaseMatters");
        foreach (string field in new[] { "script", "parameters_file", "stdin_file" }) first[field] = file;
        first["input_paths"] = new JsonArray(file); first["required_tools"] = new JsonArray(file);
        first["artifacts"] = new JsonObject { ["Report"] = f.FilePath("future.txt") };
        first["expected_versions"] = new JsonObject { [file] = FileHash(file) };
        var second = (JsonObject)first.Copy(); second["workdir"] = f.DirectoryPath.ToUpperInvariant(); second["encoding"] = "utf-8";
        foreach (string field in new[] { "script", "parameters_file", "stdin_file" }) second[field] = alias;
        second["input_paths"] = new JsonArray(alias, file); second["required_tools"] = new JsonArray(alias);
        second["artifacts"]!["Report"] = f.FilePath("future.txt").ToUpperInvariant();
        second["expected_versions"] = new JsonObject { [alias] = FileHash(file) };
        Assert.Equal(ContentIdentity.Key(first), ContentIdentity.Key(second));
        second["args"] = new JsonArray("probe", "text", "casematters"); Assert.NotEqual(ContentIdentity.Key(first), ContentIdentity.Key(second));
        second["args"] = first["args"]?.Copy(); second["artifacts"] = new JsonObject { ["report"] = f.FilePath("future.txt") };
        Assert.NotEqual(ContentIdentity.Key(first), ContentIdentity.Key(second));
    }

    [Fact, Trait("Category", "Integration")]
    public void CommittedSnapshotMustMatchItsIndexedHash()
    {
        using var f = new Fixture(); var form = f.Form("text", "reviewed");
        string id = f.Execute(form)["execution_id"].String();
        string plan = Assert.Single(Directory.GetFiles(Path.Combine(f.Serve, "_prepared"), "*.json"));
        var snapshot = Read(plan); snapshot["envelope"]!["business"]!["args"] = new JsonArray("probe", "text", "tampered");
        Save(plan, snapshot); form["encoding"] = "utf-8";
        string journal = Path.Combine(f.Serve, "publication-index.jsonl"), before = FileHash(journal);
        var response = f.Client.Raw("start_operation", form);
        Assert.True(response["isError"].IsTrue()); Assert.Contains("publication_preparation_changed", response.ToJsonString());
        Assert.Equal(before, FileHash(journal));
        Assert.Equal(id, Path.GetFileName(Assert.Single(Directory.GetDirectories(Path.Combine(f.DirectoryPath, ".codex-command-records")))));
    }

    [Fact, Trait("Category", "Integration")]
    public void AliasCannotBypassUnidentifiableLegacyClaim()
    {
        using var f = new Fixture(); var form = f.Form("text", "blocked"); string id = Guid.NewGuid().ToString();
        string claim = Path.Combine(f.Serve, "_claims", Digest(form)); Directory.CreateDirectory(claim);
        WriteNew(Path.Combine(claim, "claim.json"), new JsonObject { ["execution_id"] = id });
        string hash = FileHash(Path.Combine(claim, "claim.json")); form["encoding"] = "utf-8";
        var response = f.Client.Raw("start_operation", form);
        Assert.True(response["isError"].IsTrue()); Assert.Contains("publication_identity_unverifiable", response.ToJsonString());
        Assert.Equal(hash, FileHash(Path.Combine(claim, "claim.json")));
        Assert.False(Directory.Exists(Path.Combine(f.DirectoryPath, ".codex-command-records")));
    }

    [Theory, InlineData("running", false), InlineData("running", true), InlineData("unknown", false), InlineData("unknown", true),
        InlineData("prepared", false), InlineData("prepared", true), Trait("Category", "Integration")]
    public void ExistingLegacyOrPreparedAliasKeepsItsIdentity(string state, bool restart)
    {
        using var f = new Fixture(); var form = f.Form("text", "legacy"); form["encoding"] = "utf-8";
        string fingerprint = Digest(form);
        var business = (JsonObject)form.Copy(); business.Remove("workdir"); business["cwd"] = f.DirectoryPath;
        business["task_ref"] = "mcp-direct"; business["step_ref"] = fingerprint[..12] + "-1"; business["attempt"] = 0;
        foreach (var option in RequestShape.Options(form, f.Policy)) business[option.Key] = option.Value?.Copy();
        var request = RequestShape.Shape(business); string id = ExecutionId(request["request_id"].String());
        var envelope = new JsonObject { ["schema_version"] = 2, ["business"] = business,
            ["fingerprint"] = RequestDigest(request), ["content_fingerprint"] = fingerprint };
        string journal = Path.Combine(f.Serve, "publication-index.jsonl");
        var entry = new JsonObject { ["schema_version"] = 1, ["content_fingerprint"] = fingerprint, ["count"] = 1, ["execution_id"] = id };
        if (state == "prepared")
        {
            string preparation = Guid.NewGuid().ToString(), plans = Path.Combine(f.Serve, "_prepared"); Directory.CreateDirectory(plans);
            string plan = Path.Combine(plans, preparation + ".json");
            WriteNew(plan, new JsonObject { ["envelope"] = envelope.Copy(), ["policy"] = f.Policy.Copy(), ["previous_execution_id"] = null });
            entry["schema_version"] = 2; entry["phase"] = "prepared"; entry["preparation"] = preparation; entry["preparation_sha256"] = FileHash(plan);
        }
        else
        {
            string publication = Path.Combine(f.Serve, id); Directory.CreateDirectory(publication); WriteNew(Path.Combine(publication, "request.json"), envelope);
            string record = Path.Combine(f.DirectoryPath, ".codex-command-records", id); Directory.CreateDirectory(record);
            WriteNew(Path.Combine(record, "result.json"), new JsonObject { ["execution_id"] = id, ["state"] = state, ["owner"] = WindowsProcess.Observe(Environment.ProcessId) });
        }
        File.AppendAllText(journal, Utf8.GetString(Packed(entry)) + "\n", Utf8);
        if (restart) f.Restart();
        form.Remove("encoding"); var result = f.Start(form);
        Assert.Equal(id, result["execution_id"].String());
        if (state == "prepared")
        {
            Assert.Equal("exited", f.Terminal(id)["state"].String()); Assert.Equal("legacy\n", f.Output(id));
            JsonAssert.Equal(envelope, f.Envelope(id));
            Assert.Equal(2, File.ReadAllLines(journal).Length);
        }
        else
        {
            Assert.Equal(state == "running", result["in_flight_dedup"].IsTrue());
            Assert.Equal(state == "unknown", result["dedup_blocked"].IsTrue());
            Assert.Single(Directory.GetDirectories(Path.Combine(f.DirectoryPath, ".codex-command-records")));
        }
    }

    [Theory, InlineData(false), InlineData(true), Trait("Category", "Integration")]
    public void EquivalentRetryPreservesOriginalLineageAndChangedInputRequirement(bool artifactAlias)
    {
        using var f = new Fixture(); string input = f.Write("bound.txt", "before"); var form = f.Form("text", "retry");
        form["encoding"] = "utf-8"; form["input_paths"] = new JsonArray(input);
        if (artifactAlias)
        {
            form["artifacts"] = new JsonObject { ["Report"] = f.Write("report.txt", "result") };
            form["acceptance"] = new JsonArray(new JsonObject { ["artifact"] = "Report", ["kind"] = "exists" });
        }
        var first = f.Execute(form); Assert.Equal("exited", first["state"].String());
        File.WriteAllText(input, "after", Utf8); form.Remove("encoding"); form["previous_execution"] = first["execution_id"]?.Copy();
        if (artifactAlias) form["artifacts"]!["Report"] = form["artifacts"]!["Report"].String().ToUpperInvariant();
        var second = f.Execute(form); Assert.Equal("exited", second["state"].String());
        Assert.Equal(first["logical_id"].String(), second["logical_id"].String());
        var request = RequestShape.Shape(f.Envelope(second["execution_id"].String())["business"].Object());
        Assert.Equal(1L, request["attempt"].Integer("attempt")); Assert.Equal(first["request_id"].String(), request["previous_request"].String());
        Assert.Contains(input, second["changed_conditions"].Array().Select(value => value.String()));
        if (artifactAlias) Assert.Equal("confirmed", second["subgoal"]!["status"].String());
    }

    [Fact, Trait("Category", "Integration")]
    public void AliasRetryCanReferToEarlierLegacyInstance()
    {
        using var f = new Fixture(); string input = f.Write("bound.txt", "before"); var form = f.Form("text", "history");
        form["input_paths"] = new JsonArray(input);
        string Seed(JsonObject source, int count)
        {
            string fingerprint = Digest(source); var business = (JsonObject)source.Copy();
            business.Remove("workdir"); business["cwd"] = f.DirectoryPath; business["task_ref"] = "mcp-direct";
            business["step_ref"] = fingerprint[..12] + "-" + count; business["attempt"] = 0;
            var request = RequestShape.Shape(business); string id = ExecutionId(request["request_id"].String());
            string publication = Path.Combine(f.Serve, id), record = Path.Combine(f.DirectoryPath, ".codex-command-records", id);
            Directory.CreateDirectory(publication); Directory.CreateDirectory(record);
            WriteNew(Path.Combine(publication, "request.json"), new JsonObject { ["business"] = business,
                ["fingerprint"] = RequestDigest(request), ["content_fingerprint"] = fingerprint });
            WriteNew(Path.Combine(record, "result.json"), new JsonObject { ["state"] = "exited", ["execution_id"] = id,
                ["logical_id"] = request["logical_id"]?.Copy(), ["request"] = request.Copy(), ["bindings"] = new JsonObject { [input] = FileHash(input) } });
            File.AppendAllText(Path.Combine(f.Serve, "publication-index.jsonl"), Utf8.GetString(Packed(new JsonObject
            { ["schema_version"] = 1, ["count"] = count, ["execution_id"] = id, ["content_fingerprint"] = fingerprint })) + "\n", Utf8);
            return id;
        }
        _ = Seed(form, 1); var alias = (JsonObject)form.Copy(); alias["encoding"] = "utf-8";
        string earlier = Seed(alias, 1); _ = Seed(alias, 2);
        var origin = RequestShape.Shape(f.Envelope(earlier)["business"].Object());
        File.WriteAllText(input, "after", Utf8); form["previous_execution"] = earlier;
        var result = f.Execute(form); Assert.Equal("exited", result["state"].String());
        Assert.Equal(origin["logical_id"].String(), result["logical_id"].String());
        var retry = RequestShape.Shape(f.Envelope(result["execution_id"].String())["business"].Object());
        Assert.Equal(origin["request_id"].String(), retry["previous_request"].String()); Assert.Equal(1L, retry["attempt"].Integer("attempt"));
    }

    [Fact, Trait("Category", "Integration")]
    public void ArtifactEquivalenceDoesNotChangeNamesOrLocations()
    {
        using var f = new Fixture(); string path = f.FilePath("out.txt");
        var before = new JsonObject { ["Report"] = path };
        Assert.True(BusinessPaths.SameArtifacts(before, new JsonObject { ["Report"] = path.ToUpperInvariant() }));
        Assert.False(BusinessPaths.SameArtifacts(before, new JsonObject { ["report"] = path }));
        Assert.False(BusinessPaths.SameArtifacts(before, new JsonObject { ["Report"] = f.FilePath("other.txt") }));
        Assert.False(BusinessPaths.SameArtifacts(before, new JsonObject()));
    }
}
