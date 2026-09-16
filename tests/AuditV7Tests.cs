using System.Text.Json.Nodes;
using CommandEntry;
using static CommandEntry.RecordJson;

namespace CommandEntry.Tests;

[Trait("Suite", "Regression")]
public sealed class AuditV7Tests
{
    private static (string Id, string Fingerprint, JsonObject Entry, JsonObject Envelope, string Plan) SeedPrepared(Fixture f, JsonObject form, int stage, bool oldClaim, JsonObject? previous = null)
    {
        string fingerprint = Digest(form);
        long count = oldClaim ? 2 : 1;
        var business = form.Object().Select(p => KeyValuePair.Create(p.Key, p.Value?.Copy())).ToArray();
        var requestBusiness = new JsonObject(business);
        requestBusiness.Remove("workdir");
        requestBusiness["cwd"] = f.DirectoryPath;
        requestBusiness["task_ref"] = "mcp-direct"; requestBusiness["step_ref"] = fingerprint[..12] + "-" + count;
        requestBusiness["attempt"] = 0;
        if (previous is not null)
        {
            var origin = RequestShape.Shape(previous["business"].Object());
            requestBusiness["task_ref"] = origin["task_ref"]?.Copy(); requestBusiness["step_ref"] = origin["step_ref"]?.Copy();
            requestBusiness["attempt"] = origin["attempt"].Integer("attempt") + 1;
            requestBusiness["previous_request"] = origin["request_id"]?.Copy();
        }
        foreach (var option in RequestShape.Options(form, f.Policy)) requestBusiness[option.Key] = option.Value?.Copy();
        var request = RequestShape.Shape(requestBusiness);
        string id = ExecutionId(request["request_id"].String()), preparation = Guid.NewGuid().ToString();
        var envelope = new JsonObject { ["schema_version"] = 2, ["business"] = requestBusiness,
            ["fingerprint"] = RequestDigest(request), ["content_fingerprint"] = fingerprint };
        string plans = Path.Combine(f.Serve, "_prepared"); Directory.CreateDirectory(plans);
        string plan = Path.Combine(plans, preparation + ".json");
        string oldClaimPath = Path.Combine(f.Serve, "_claims", fingerprint, "claim.json");
        WriteNew(plan, new JsonObject { ["envelope"] = envelope.Copy(), ["policy"] = f.Policy.Copy(),
            ["previous_execution_id"] = File.Exists(oldClaimPath) ? Read(oldClaimPath)["execution_id"]?.Copy() : null });
        var entry = new JsonObject { ["schema_version"] = 2, ["content_fingerprint"] = fingerprint, ["execution_id"] = id,
            ["count"] = count, ["phase"] = "prepared", ["preparation"] = preparation, ["preparation_sha256"] = FileHash(plan) };
        File.AppendAllText(Path.Combine(f.Serve, "publication-index.jsonl"), Utf8.GetString(Packed(entry)) + "\n", Utf8);
        string directory = Path.Combine(f.Serve, id);
        if (stage >= 1) Directory.CreateDirectory(directory);
        if (stage >= 2) WriteNew(Path.Combine(directory, "request.json"), envelope);
        if (stage >= 3) WriteNew(Path.Combine(directory, "policy.json"), f.Policy);
        if (stage >= 4)
        {
            string claim = Path.Combine(f.Serve, "_claims", fingerprint); Directory.CreateDirectory(claim);
            Save(Path.Combine(claim, "claim.json"), new JsonObject { ["execution_id"] = id });
        }
        return (id, fingerprint, entry, envelope, plan);
    }

    public static TheoryData<int, bool, bool> InterruptedStages
    {
        get
        {
            var data = new TheoryData<int, bool, bool>();
            foreach (int stage in Enumerable.Range(0, 5))
            foreach (bool oldClaim in new[] { false, true })
            foreach (bool restart in new[] { false, true }) data.Add(stage, oldClaim, restart);
            return data;
        }
    }

    [Theory, MemberData(nameof(InterruptedStages)), Trait("Category", "Integration")]
    public void PreparedPublicationResumesOriginalIdentity(int stage, bool oldClaim, bool restart)
    {
        using var f = new Fixture();
        var form = f.Form("text", "恢复 😀");
        Assert.Equal("exited", f.Execute(oldClaim ? form : f.Form("text", "warmup"))["state"].Text());
        var prepared = SeedPrepared(f, form, stage, oldClaim);
        string hash = FileHash(prepared.Plan);
        if (restart) f.Restart();
        // Resource limits are not part of content identity; recovery keeps the original plan.
        form["run_seconds"] = 10;
        var start = f.Start(form);
        Assert.Equal(prepared.Id, start["execution_id"].String());
        var result = f.Terminal(prepared.Id);
        Assert.Equal("exited", result["state"].Text());
        Assert.Equal(0L, result["process"]!["exit_code"].Integer("exit"));
        Assert.Equal("恢复 😀\n", f.Output(prepared.Id));
        JsonAssert.Equal(prepared.Envelope, f.Envelope(prepared.Id));
        Assert.Equal(hash, FileHash(prepared.Plan));
        var entries = File.ReadLines(Path.Combine(f.Serve, "publication-index.jsonl"), Utf8)
            .Select(line => JsonNode.Parse(line).Object()).Where(e => e["content_fingerprint"].Text() == prepared.Fingerprint).ToArray();
        Assert.Equal("launch_committed", entries[^1]["phase"].Text());
        Assert.Equal(prepared.Id, entries[^1]["execution_id"].Text());
        Assert.Equal(prepared.Entry["count"]!.GetValue<long>(), entries[^1]["count"]!.GetValue<long>());
        Assert.True(File.Exists(Path.Combine(result["record_dir"].String(), "business-process.json")));
    }

    [Theory, InlineData("legacy"), InlineData("committed"), InlineData("plan_changed"), InlineData("policy_changed"), InlineData("record_exists"), InlineData("request_changed"), Trait("Category", "Integration")]
    public void UnprovenOrConflictingPublicationDoesNotLaunch(string condition)
    {
        using var f = new Fixture(); var form = f.Form("text", "must-not-launch");
        var prepared = SeedPrepared(f, form, 3, false);
        string journal = Path.Combine(f.Serve, "publication-index.jsonl");
        if (condition == "legacy")
        {
            // Separate legacy fixture: retain the prepared journal as evidence.
            File.Move(journal, journal + ".prepared");
            var legacy = new JsonObject { ["schema_version"] = 1, ["content_fingerprint"] = prepared.Fingerprint,
                ["execution_id"] = prepared.Id, ["count"] = 1 };
            File.AppendAllText(journal, Utf8.GetString(Packed(legacy)) + "\n", Utf8);
        }
        if (condition == "committed")
        {
            var committed = (JsonObject)prepared.Entry.Copy(); committed["phase"] = "launch_committed";
            File.AppendAllText(journal, Utf8.GetString(Packed(committed)) + "\n", Utf8);
        }
        if (condition == "plan_changed") File.AppendAllText(prepared.Plan, " ", Utf8);
        if (condition == "policy_changed") { f.Policy["wait_budget_seconds"] = 2; f.Restart(); }
        string record = Path.Combine(f.DirectoryPath, ".codex-command-records", prepared.Id);
        if (condition == "record_exists") Directory.CreateDirectory(record);
        if (condition == "request_changed")
        {
            var changed = (JsonObject)prepared.Envelope.Copy(); changed["fingerprint"] = "conflicting-evidence";
            Save(Path.Combine(f.Serve, prepared.Id, "request.json"), changed);
        }
        string before = FileHash(journal), requestHash = FileHash(Path.Combine(f.Serve, prepared.Id, "request.json"));
        var response = f.Client.Raw("start_operation", form);
        if (condition is "legacy" or "committed")
        {
            Assert.False(response["isError"].IsTrue(), response.ToJsonString());
            Assert.True(response["structuredContent"]!["dedup_blocked"].IsTrue());
            Assert.Equal(prepared.Id, response["structuredContent"]!["execution_id"].Text());
        }
        else
        {
            Assert.True(response["isError"].IsTrue(), response.ToJsonString());
            string expected = condition switch
            {
                "plan_changed" => "publication_preparation_changed",
                "policy_changed" => "publication_preparation_policy_changed",
                "record_exists" => "execution_identity_already_recorded",
                _ => "publication_file_conflict"
            };
            Assert.Contains(expected, response.ToJsonString());
        }
        Assert.Equal(before, FileHash(journal));
        Assert.Equal(requestHash, FileHash(Path.Combine(f.Serve, prepared.Id, "request.json")));
        Assert.False(File.Exists(Path.Combine(record, "business-process.json")));
    }

    [Theory, InlineData("missing_preparation"), InlineData("different_identity"), InlineData("different_hash"),
        InlineData("duplicate_preparation"), InlineData("superseded_preparation"), InlineData("invalid_phase"), Trait("Category", "Integration")]
    public void InvalidPublicationTransitionsPreserveEvidence(string condition)
    {
        using var f = new Fixture(); var form = f.Form("text", "uncommitted");
        var prepared = SeedPrepared(f, form, 0, false);
        string journal = Path.Combine(f.Serve, "publication-index.jsonl");
        var transition = (JsonObject)prepared.Entry.Copy(); transition["phase"] = "launch_committed";
        string expected = "publication_commit_without_matching_preparation";
        switch (condition)
        {
            case "missing_preparation": File.Move(journal, journal + ".original"); break;
            case "different_identity": transition["execution_id"] = Guid.NewGuid().ToString(); break;
            case "different_hash": transition["preparation_sha256"] = new string('0', 64); break;
            case "duplicate_preparation": transition["phase"] = "prepared"; expected = "publication_index_count_not_increasing"; break;
            case "superseded_preparation": transition["phase"] = "prepared"; transition["count"] = 2; expected = "publication_preparation_uncommitted"; break;
            case "invalid_phase": transition["phase"] = "unknown"; expected = "publication_index_phase_invalid"; break;
        }
        File.AppendAllText(journal, Utf8.GetString(Packed(transition)) + "\n", Utf8);
        string hash = FileHash(journal);
        var response = f.Client.Raw("start_operation", form);
        Assert.True(response["isError"].IsTrue());
        Assert.Contains(expected, response.ToJsonString());
        Assert.Equal(hash, FileHash(journal));
        Assert.False(Directory.Exists(Path.Combine(f.DirectoryPath, ".codex-command-records", prepared.Id)));
    }

    [Fact, Trait("Category", "Integration")]
    public async Task ConcurrentRecoveryKeepsOneIdentityAndCommit()
    {
        using var f = new Fixture(); using var second = new McpClient(f.PolicyPath);
        var form = f.Form("sleep", "5000"); var prepared = SeedPrepared(f, form, 2, false);
        using var start = new ManualResetEventSlim();
        var tasks = new[] { f.Client, second }.Select(client => Task.Run(() =>
        { start.Wait(); return client.Raw("start_operation", form); })).ToArray();
        start.Set();
        var responses = await Task.WhenAll(tasks).WaitAsync(TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken);
        Assert.Contains(responses, response => !response["isError"].IsTrue());
        foreach (var response in responses)
            if (response["isError"].IsTrue()) Assert.Contains("claim_pending_unconfirmed_retry_later", response.ToJsonString());
            else Assert.Equal(prepared.Id, response["structuredContent"]!["execution_id"].Text());
        Assert.Equal("exited", f.Terminal(prepared.Id)["state"].Text());
        var entries = File.ReadLines(Path.Combine(f.Serve, "publication-index.jsonl"), Utf8).Select(line => JsonNode.Parse(line).Object()).ToArray();
        Assert.Equal(2, entries.Length);
        Assert.Equal("prepared", entries[0]["phase"].Text()); Assert.Equal("launch_committed", entries[1]["phase"].Text());
        Assert.All(entries, entry => Assert.Equal(prepared.Id, entry["execution_id"].Text()));
    }

    [Fact, Trait("Category", "Integration")]
    public void RecoveryRetainsRetryLineageAndChangedInputCheck()
    {
        using var f = new Fixture();
        string input = f.Write("bound.txt", "before");
        var form = f.Form("text", "retry"); form["input_paths"] = new JsonArray(input);
        var original = f.Execute(form); Assert.Equal("exited", original["state"].Text());
        string priorId = original["execution_id"].String();
        var prior = f.Envelope(priorId);
        File.AppendAllText(input, "-changed", Utf8);
        var prepared = SeedPrepared(f, form, 3, true, prior);
        form["previous_execution"] = priorId; f.Restart();
        Assert.Equal(prepared.Id, f.Start(form)["execution_id"].Text());
        var result = f.Terminal(prepared.Id);
        Assert.Equal("exited", result["state"].Text());
        Assert.Equal(0L, result["process"]!["exit_code"].Integer("exit"));
        Assert.Contains(input, result["changed_conditions"].Array().Select(item => item.String()));
        var business = f.Envelope(prepared.Id)["business"].Object();
        Assert.Equal(1L, business["attempt"].Integer("attempt"));
        Assert.Equal(RequestShape.Shape(prior["business"].Object())["request_id"].Text(), business["previous_request"].Text());
    }

    [Fact, Trait("Category", "Integration")]
    public void RecoveryPreservesRecordedPublicationFailure()
    {
        using var f = new Fixture(); var form = f.Form("text", "new-intent");
        var prepared = SeedPrepared(f, form, 3, false);
        string failure = Path.Combine(f.Serve, prepared.Id, "serve-error.json");
        WriteNew(failure, new JsonObject { ["schema_version"] = 2, ["state"] = "not_started", ["execution_id"] = prepared.Id,
            ["error"] = new JsonObject { ["kind"] = "OSError", ["reason"] = "recorded publication failure" } });
        string hash = FileHash(failure);
        var start = f.Start(form);
        Assert.Equal(prepared.Id, start["execution_id"].Text()); Assert.Equal("start_failed", start["state"].Text());
        Assert.False(Directory.Exists(start["record_dir"].String()));
        Assert.Equal(hash, FileHash(failure));
        var next = f.Execute(form);
        Assert.NotEqual(prepared.Id, next["execution_id"].Text()); Assert.Equal("exited", next["state"].Text());
        Assert.Equal(hash, FileHash(failure));
    }

    [Fact, Trait("Category", "Integration")]
    public void ConcurrentWaitReportsConflictWithoutChangingProgress()
    {
        using var f = new Fixture();
        var state = f.Execute(f.Form("text", "wait"));
        string id = state["execution_id"].String(), directory = state["record_dir"].String();
        string progress = Path.Combine(directory, "wait-state.json");
        WriteNew(progress, new JsonObject { ["count"] = 7, ["previous"] = null });
        string before = FileHash(progress);
        using (var held = new FileMutex(Path.Combine(directory, "wait-state.lock")))
        {
            var response = f.Client.Raw("wait", new JsonObject { ["execution_id"] = id });
            Assert.True(response["isError"].IsTrue());
            var detail = JsonNode.Parse(response["content"]![0]!["text"].String()).Object();
            Assert.Equal("Invalid", detail["error"].Text());
            Assert.Equal("wait_in_progress_retry_later", detail["reason"].Text());
            Assert.True(detail["rejection_audit"]!["recorded"].IsTrue());
            Assert.Equal(before, FileHash(progress));
        }
        Assert.Equal("terminal", f.Client.Call("wait", new JsonObject { ["execution_id"] = id })["wait_outcome"].Text());
    }

    [Fact, Trait("Category", "Unit")]
    public void HandshakeValuesRemainAsciiAndRoundTrip()
    {
        var message = new JsonObject { ["handshake"] = "job_assigned", ["cwd"] = @"C:\用户\工作 😀",
            ["record_dir"] = @"C:\记录\e\u0301", ["argv"] = new JsonArray("工具.exe", "中文 😀 e\u0301\n\t"),
            ["stdin_file"] = @"C:\输入.txt", ["powershell_request"] = @"C:\参数.json" };
        byte[] bytes = Packed(message);
        Assert.All(bytes, value => Assert.InRange(value, (byte)0, (byte)127));
        Assert.True(JsonNode.DeepEquals(message, JsonNode.Parse(bytes)));
    }

    [Fact, Trait("Category", "Integration")]
    public async Task ConcurrentServersRetainEverySuccessEvent()
    {
        using var f = new Fixture(); string path = f.Write("read.txt", "ok");
        McpClient[] clients = Enumerable.Range(0, 4).Select(_ => new McpClient(f.PolicyPath)).ToArray();
        try
        {
            using var ready = new CountdownEvent(clients.Length);
            using var start = new ManualResetEventSlim();
            var calls = clients.Select(client => Task.Run(() =>
            {
                ready.Signal(); start.Wait();
                for (int i = 0; i < 200; i++)
                    Assert.Equal("ok", client.Call("read_text", new JsonObject { ["file"] = path })["text"].Text());
            })).ToArray();
            Assert.True(ready.Wait(TimeSpan.FromSeconds(15), TestContext.Current.CancellationToken));
            start.Set();
            await Task.WhenAll(calls).WaitAsync(TimeSpan.FromSeconds(45), TestContext.Current.CancellationToken);
            var events = File.ReadLines(f.FilePath("logs/server-events.jsonl"), Utf8).Select(line => JsonNode.Parse(line).Object()).ToArray();
            Assert.Equal(800, events.Count(e => e["kind"].Text() == "read_text"));
        }
        finally { foreach (var client in clients) client.Dispose(); }
    }
}
