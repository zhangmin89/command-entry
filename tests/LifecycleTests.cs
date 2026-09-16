using System.Diagnostics;
using System.Text.Json.Nodes;
using CommandEntry;
using static CommandEntry.RecordJson;

namespace CommandEntry.Tests;

public sealed class LifecycleTests
{
    [Fact, Trait("Category", "Integration")]
    public void CancelConfirmsWorkerAndBusinessExit()
    {
        using var f = new Fixture(); f.Policy["cancel_grace_seconds"] = 15; f.Restart();
        var start = f.Start(f.Form("sleep", "40000")); string id = start["execution_id"].String();
        var cancelled = f.Client.Call("cancel", new JsonObject { ["execution_id"] = id });
        Assert.Equal("cancelled", cancelled["state"].String()); var state = f.Terminal(id);
        Assert.False(state["worker_observation"]!["alive"].IsTrue());
        var birth = state["business_start"].Object(); var current = WindowsProcess.Observe(birth.Int("pid", 0));
        Assert.True(current["alive"]?.GetValue<bool>() == false || current["creation_time"]?.ToJsonString() != birth["creation_time"]?.ToJsonString());
        Assert.Equal("already_terminal", f.Client.Call("cancel", new JsonObject { ["execution_id"] = id })["cancel_action"].String());
    }

    [Fact, Trait("Category", "Integration")]
    public void WaitStopsWithoutClaimingTermination()
    {
        using var f = new Fixture(); f.Policy["wait_poll_interval_seconds"] = 1; f.Policy["wait_budget_seconds"] = 5; f.Policy["wait_stop_after_no_progress"] = 2; f.Restart();
        var start = f.Start(f.Form("sleep", "30000")); string id = start["execution_id"].String();
        var result = f.Client.Call("wait", new JsonObject { ["execution_id"] = id });
        Assert.Equal("stop_automatic_wait", result["wait_outcome"].String()); Assert.True(result["no_progress_count"].Integer("count") >= 2);
        Assert.True(result["observation"]!["process_alive"].IsTrue()); Assert.False(result["observation"]!["progress_confirmed"].IsTrue());
        // Stop waiting at the policy signal; explicitly cancel this test-owned process.
        var cancelled = f.Client.Call("cancel", new JsonObject { ["execution_id"] = id });
        Assert.True(cancelled["state"].Text() == "cancelled" || cancelled["confirmed_dead"].IsTrue(), cancelled.ToJsonString());
    }

    [Fact, Trait("Category", "Integration")]
    public void WaitBudgetAndTerminalResults()
    {
        using var f = new Fixture(); f.Policy["wait_poll_interval_seconds"] = 1; f.Policy["wait_budget_seconds"] = 1; f.Policy["wait_stop_after_no_progress"] = 20; f.Restart();
        var start = f.Start(f.Form("sleep", "3000")); string id = start["execution_id"].String();
        var result = f.Client.Call("wait", new JsonObject { ["execution_id"] = id }); Assert.Equal("budget_exhausted", result["wait_outcome"].String());
        Assert.True(result["observation"] is JsonObject); Assert.Equal("exited", f.Terminal(id)["state"].String());
        Assert.Equal("terminal", f.Client.Call("wait", new JsonObject { ["execution_id"] = id })["wait_outcome"].String());
    }

    [Fact, Trait("Category", "Integration")]
    public void CorruptWaitStateIsPreserved()
    {
        using var f = new Fixture(); var start = f.Start(f.Form("sleep", "30000")); string id = start["execution_id"].String();
        string journal = Path.Combine(start["record_dir"].String(), "wait-state.json"); File.WriteAllText(journal, "{broken", Utf8);
        var result = f.Client.Raw("wait", new JsonObject { ["execution_id"] = id }); Assert.True(result["isError"].IsTrue());
        Assert.Equal("{broken", File.ReadAllText(journal));
        var cancelled = f.Client.Call("cancel", new JsonObject { ["execution_id"] = id });
        Assert.True(cancelled["state"].Text() == "cancelled" || cancelled["confirmed_dead"].IsTrue(), cancelled.ToJsonString());
    }

    [Fact, Trait("Category", "Integration")]
    public void CrossServerClaimRecoveryKeepsSameExecution()
    {
        using var f = new Fixture(); var form = f.Form("sleep", "10000"); var first = f.Start(form); string id = first["execution_id"].String();
        string claim = Path.Combine(f.Serve, "_claims", f.Envelope(id)["content_fingerprint"].String(), "claim.json");
        using var second = new McpClient(f.PolicyPath);
        foreach (string bad in new[] { "{", "[]", "{}", "{\"execution_id\":7}", "{\"execution_id\":\"../outside\"}" })
        {
            File.WriteAllText(claim, bad, Utf8); var result = second.Call("start_operation", form);
            Assert.Equal(id, result["execution_id"].String()); Assert.True(result["in_flight_dedup"].IsTrue()); Assert.Equal(id, Read(claim)["execution_id"].String());
        }
        var cancel = f.Client.Call("cancel", new JsonObject { ["execution_id"] = id });
        Assert.True(cancel["state"].Text() == "cancelled" || cancel["confirmed_dead"].IsTrue(), cancel.ToJsonString());
    }

    [Fact, Trait("Category", "Integration")]
    public void OwnerSurvivesMcpServerExit()
    {
        using var f = new Fixture(); var start = f.Start(f.Form("sleep", "2000")); string id = start["execution_id"].String();
        f.Client.Process.Kill(); Assert.True(f.Client.Process.WaitForExit(10000)); f.Restart();
        Assert.Equal("exited", f.Terminal(id)["state"].String()); Assert.Equal("survived\n", f.Output(id));
    }

    [Fact, Trait("Category", "Integration")]
    public void UnknownBlocksUntilCancellationConfirmsAbandonment()
    {
        using var f = new Fixture(); var form = f.Form("sleep", "3000"); var start = f.Start(form); string id = start["execution_id"].String();
        var stored = Read(Path.Combine(start["record_dir"].String(), "result.json")); var owner = stored["owner"].Object();
        using (var process = Process.GetProcessById(owner.Int("pid", 0)))
        {
            Assert.True(WindowsProcess.TerminateSameInstance(owner.Int("pid", 0), owner["creation_time"]!.GetValue<ulong>())["terminated"].IsTrue());
            Assert.True(process.WaitForExit(10000));
        }
        var blocked = f.Start(form); Assert.Equal(id, blocked["execution_id"].String()); Assert.True(blocked["dedup_blocked"].IsTrue());
        var cancelled = f.Client.Call("cancel", new JsonObject { ["execution_id"] = id }); Assert.True(cancelled["confirmed_dead"].IsTrue(), cancelled.ToJsonString());
        Assert.Equal("unknown", f.Client.Call("status", new JsonObject { ["execution_id"] = id })["state"].String());
        var next = f.Execute(form); Assert.True(next["execution_id"].String() != id); Assert.Equal("exited", next["state"].String());
    }

    [Fact, Trait("Category", "Integration")]
    public void PublicationFailureIsQueryableWithoutStartingBusiness()
    {
        using var f = new Fixture(); var form = f.Form("location");
        string claim = Path.Combine(f.Serve, "_claims", Digest(form), "claim.json"); Directory.CreateDirectory(claim);
        var result = f.Start(form); string id = result["execution_id"].String(); Assert.Equal("start_failed", result["state"].String());
        Assert.False(Directory.Exists(result["record_dir"].String()));
        Assert.Equal("start_failed", f.Client.Call("status", new JsonObject { ["execution_id"] = id })["state"].String());
        Assert.Equal("already_terminal", f.Client.Call("cancel", new JsonObject { ["execution_id"] = id })["cancel_action"].String());
    }

    [Fact, Trait("Category", "Integration")]
    public void PendingClaimAndUnrecoverableCorruptionFailClosed()
    {
        using var f = new Fixture(); var form = f.Form("location"); string directory = Path.Combine(f.Serve, "_claims", Digest(form)); Directory.CreateDirectory(directory);
        using (var mutex = new FileMutex(Path.Combine(directory, "claim.lock")))
        {
            var result = f.Client.Raw("start_operation", form); Assert.True(result["isError"].IsTrue()); Assert.Contains("claim_pending_unconfirmed_retry_later", result.ToJsonString());
        }
        string claim = Path.Combine(directory, "claim.json"); File.WriteAllText(claim, "{", Utf8);
        var broken = f.Client.Raw("start_operation", form); Assert.True(broken["isError"].IsTrue()); Assert.Contains("claim_record_unreadable", broken.ToJsonString());
        Assert.Equal("{", File.ReadAllText(claim)); Assert.Empty(Directory.GetFiles(f.Serve, "request.json", SearchOption.AllDirectories));
    }

    [Fact, Trait("Category", "Integration")]
    public void CorruptHistoryIsLoggedAndClaimTargetsDoNotFallBack()
    {
        using var f = new Fixture(); string unrelated = Path.Combine(f.Serve, Guid.NewGuid().ToString()); Directory.CreateDirectory(unrelated);
        string broken = Path.Combine(unrelated, "request.json"); File.WriteAllText(broken, "{", Utf8);
        var form = f.Form("location"); var first = f.Execute(form); Assert.Equal("exited", first["state"].String());
        var events = File.ReadLines(f.FilePath("logs/server-events.jsonl")).Select(line => JsonNode.Parse(line).Object()).ToArray();
        Assert.Contains(events, item => item["kind"].Text() == "request_record_unreadable" && item["file"].Text() == broken); Assert.Equal("{", File.ReadAllText(broken));
        string target = Path.Combine(f.Serve, first["execution_id"].String(), "request.json"); File.WriteAllText(target, "{", Utf8);
        var result = f.Client.Raw("start_operation", form); Assert.True(result["isError"].IsTrue()); Assert.Contains("request_record_unreadable", result.ToJsonString());
        Assert.Equal("{", File.ReadAllText(target));
    }

    [Fact, Trait("Category", "Integration")]
    public void StartupFailureSidecarNeverOverridesExistingResult()
    {
        using var f = new Fixture(); string id = Guid.NewGuid().ToString(); string serve = Path.Combine(f.Serve, id); Directory.CreateDirectory(serve);
        WriteNew(Path.Combine(serve, "request.json"), new JsonObject { ["business"] = new JsonObject { ["cwd"] = f.DirectoryPath } });
        var query = new JsonObject { ["execution_id"] = id }; Assert.Equal("unknown", f.Client.Call("status", query)["state"].String());
        string sidecar = Path.Combine(serve, "serve-error.json"); var failure = new JsonObject { ["state"] = "not_started", ["execution_id"] = null,
            ["error"] = new JsonObject { ["kind"] = "OSError", ["reason"] = "synthetic failure" } };
        WriteNew(sidecar, failure); Assert.Equal("start_failed", f.Client.Call("status", query)["state"].String());
        foreach (string invalid in new[] { "{", "[]", "{}", "{\"state\":\"running\"}", "{\"state\":\"not_started\",\"error\":{\"kind\":\"OSError\",\"reason\":7}}" })
        { File.WriteAllText(sidecar, invalid, Utf8); Assert.Equal("unknown", f.Client.Call("status", query)["state"].String()); }
        Save(sidecar, failure); string record = Path.Combine(f.DirectoryPath, ".codex-command-records", id); Directory.CreateDirectory(record);
        foreach (string state in new[] { "exited", "unknown" })
        {
            Save(Path.Combine(record, "result.json"), new JsonObject { ["state"] = state, ["execution_id"] = id, ["reason"] = "existing result" });
            var result = f.Client.Call("status", query); Assert.Equal(state, result["state"].String()); Assert.False(result.ContainsKey("serve_error"));
        }
    }

    [Fact, Trait("Category", "Integration")]
    public void HalfPublishedHistoryRemainsBlocked()
    {
        using var f = new Fixture(); var form = f.Form("location"); string fingerprint = Digest(form), id = Guid.NewGuid().ToString();
        string serve = Path.Combine(f.Serve, id); Directory.CreateDirectory(serve);
        WriteNew(Path.Combine(serve, "request.json"), new JsonObject { ["content_fingerprint"] = fingerprint, ["business"] = new JsonObject { ["cwd"] = f.DirectoryPath } });
        var blocked = f.Start(form); Assert.Equal(id, blocked["execution_id"].String()); Assert.True(blocked["dedup_blocked"].IsTrue());
        Assert.False(Directory.Exists(Path.Combine(f.DirectoryPath, ".codex-command-records", id)));
    }

    [Fact, Trait("Category", "Integration")]
    public void WorkerRejectsMissingOrEmptyArgv()
    {
        foreach (var (input, reason) in new[] { ("{\"handshake\":\"job_assigned\"}\n", "array_required"), ("{\"handshake\":\"job_assigned\",\"argv\":[]}\n", "worker_argv_required") })
        {
            var result = Fixture.Run(TestEnvironment.Server, ["worker"], input); Assert.Equal(125, result.Exit);
            var error = JsonNode.Parse(result.Error).Object(); Assert.Equal("Invalid", error["kind"].String()); Assert.Equal(reason, error["reason"].String());
        }
    }
}
