using System.Diagnostics;
using System.Text.Json.Nodes;
using CommandEntry;
using static CommandEntry.RecordJson;

namespace CommandEntry.Tests;

internal static class LifecycleTests
{
    [Case]
    private static void CancelConfirmsWorkerAndBusinessExit()
    {
        using var f = new Fixture(); f.Policy["cancel_grace_seconds"] = 15; f.Restart();
        var start = f.Start(f.Form("sleep", "40000")); string id = start["execution_id"].String();
        var cancelled = f.Client.Call("cancel", new JsonObject { ["execution_id"] = id });
        Check.Equal("cancelled", cancelled["state"].String()); var state = f.Terminal(id);
        Check.True(!state["worker_observation"]!["alive"].IsTrue());
        var birth = state["business_start"].Object(); var current = WindowsProcess.Observe(birth.Int("pid", 0));
        Check.True(current["alive"]?.GetValue<bool>() == false || current["creation_time"]?.ToJsonString() != birth["creation_time"]?.ToJsonString());
        Check.Equal("already_terminal", f.Client.Call("cancel", new JsonObject { ["execution_id"] = id })["cancel_action"].String());
    }

    [Case]
    private static void WaitStopsWithoutClaimingTermination()
    {
        using var f = new Fixture(); f.Policy["wait_poll_interval_seconds"] = 1; f.Policy["wait_budget_seconds"] = 5; f.Policy["wait_stop_after_no_progress"] = 2; f.Restart();
        var start = f.Start(f.Form("sleep", "30000")); string id = start["execution_id"].String();
        var result = f.Client.Call("wait", new JsonObject { ["execution_id"] = id });
        Check.Equal("stop_automatic_wait", result["wait_outcome"].String()); Check.True(result["no_progress_count"].Integer("count") >= 2);
        Check.True(result["observation"]!["process_alive"].IsTrue()); Check.True(!result["observation"]!["progress_confirmed"].IsTrue());
        // Stop waiting at the policy signal; explicitly cancel this test-owned process.
        var cancelled = f.Client.Call("cancel", new JsonObject { ["execution_id"] = id });
        Check.True(cancelled["state"].Text() == "cancelled" || cancelled["confirmed_dead"].IsTrue(), cancelled.ToJsonString());
    }

    [Case]
    private static void WaitBudgetAndTerminalResults()
    {
        using var f = new Fixture(); f.Policy["wait_poll_interval_seconds"] = 1; f.Policy["wait_budget_seconds"] = 1; f.Policy["wait_stop_after_no_progress"] = 20; f.Restart();
        var start = f.Start(f.Form("sleep", "3000")); string id = start["execution_id"].String();
        var result = f.Client.Call("wait", new JsonObject { ["execution_id"] = id }); Check.Equal("budget_exhausted", result["wait_outcome"].String());
        Check.True(result["observation"] is JsonObject); Check.Equal("exited", f.Terminal(id)["state"].String());
        Check.Equal("terminal", f.Client.Call("wait", new JsonObject { ["execution_id"] = id })["wait_outcome"].String());
    }

    [Case]
    private static void CorruptWaitStateIsPreserved()
    {
        using var f = new Fixture(); var start = f.Start(f.Form("sleep", "30000")); string id = start["execution_id"].String();
        string journal = Path.Combine(start["record_dir"].String(), "wait-state.json"); File.WriteAllText(journal, "{broken", Utf8);
        var result = f.Client.Raw("wait", new JsonObject { ["execution_id"] = id }); Check.True(result["isError"].IsTrue());
        Check.Equal("{broken", File.ReadAllText(journal));
        var cancelled = f.Client.Call("cancel", new JsonObject { ["execution_id"] = id });
        Check.True(cancelled["state"].Text() == "cancelled" || cancelled["confirmed_dead"].IsTrue(), cancelled.ToJsonString());
    }

    [Case]
    private static void CrossServerClaimRecoveryKeepsSameExecution()
    {
        using var f = new Fixture(); var form = f.Form("sleep", "10000"); var first = f.Start(form); string id = first["execution_id"].String();
        string claim = Path.Combine(f.Serve, "_claims", f.Envelope(id)["content_fingerprint"].String(), "claim.json");
        using var second = new McpClient(f.PolicyPath);
        foreach (string bad in new[] { "{", "[]", "{}", "{\"execution_id\":7}", "{\"execution_id\":\"../outside\"}" })
        {
            File.WriteAllText(claim, bad, Utf8); var result = second.Call("start_operation", form);
            Check.Equal(id, result["execution_id"].String()); Check.True(result["in_flight_dedup"].IsTrue()); Check.Equal(id, Read(claim)["execution_id"].String());
        }
        var cancel = f.Client.Call("cancel", new JsonObject { ["execution_id"] = id });
        Check.True(cancel["state"].Text() == "cancelled" || cancel["confirmed_dead"].IsTrue(), cancel.ToJsonString());
    }

    [Case]
    private static void OwnerSurvivesMcpServerExit()
    {
        using var f = new Fixture(); var start = f.Start(f.Form("sleep", "2000")); string id = start["execution_id"].String();
        f.Client.Process.Kill(); Check.True(f.Client.Process.WaitForExit(10000)); f.Restart();
        Check.Equal("exited", f.Terminal(id)["state"].String()); Check.Equal("survived\n", f.Output(id));
    }

    [Case]
    private static void UnknownBlocksUntilCancellationConfirmsAbandonment()
    {
        using var f = new Fixture(); var form = f.Form("sleep", "3000"); var start = f.Start(form); string id = start["execution_id"].String();
        var stored = Read(Path.Combine(start["record_dir"].String(), "result.json")); var owner = stored["owner"].Object();
        using (var process = Process.GetProcessById(owner.Int("pid", 0)))
        {
            Check.True(WindowsProcess.TerminateSameInstance(owner.Int("pid", 0), owner["creation_time"]!.GetValue<ulong>())["terminated"].IsTrue());
            Check.True(process.WaitForExit(10000));
        }
        var blocked = f.Start(form); Check.Equal(id, blocked["execution_id"].String()); Check.True(blocked["dedup_blocked"].IsTrue());
        var cancelled = f.Client.Call("cancel", new JsonObject { ["execution_id"] = id }); Check.True(cancelled["confirmed_dead"].IsTrue(), cancelled.ToJsonString());
        Check.Equal("unknown", f.Client.Call("status", new JsonObject { ["execution_id"] = id })["state"].String());
        var next = f.Execute(form); Check.True(next["execution_id"].String() != id); Check.Equal("exited", next["state"].String());
    }

    [Case]
    private static void PublicationFailureIsQueryableWithoutStartingBusiness()
    {
        using var f = new Fixture(); var form = f.Form("location");
        string claim = Path.Combine(f.Serve, "_claims", Digest(form), "claim.json"); Directory.CreateDirectory(claim);
        var result = f.Start(form); string id = result["execution_id"].String(); Check.Equal("start_failed", result["state"].String());
        Check.True(!Directory.Exists(result["record_dir"].String()));
        Check.Equal("start_failed", f.Client.Call("status", new JsonObject { ["execution_id"] = id })["state"].String());
        Check.Equal("already_terminal", f.Client.Call("cancel", new JsonObject { ["execution_id"] = id })["cancel_action"].String());
    }

    [Case]
    private static void PendingClaimAndUnrecoverableCorruptionFailClosed()
    {
        using var f = new Fixture(); var form = f.Form("location"); string directory = Path.Combine(f.Serve, "_claims", Digest(form)); Directory.CreateDirectory(directory);
        using (var mutex = new FileMutex(Path.Combine(directory, "claim.lock")))
        {
            var result = f.Client.Raw("start_operation", form); Check.True(result["isError"].IsTrue()); Check.Contains("claim_pending_unconfirmed_retry_later", result.ToJsonString());
        }
        string claim = Path.Combine(directory, "claim.json"); File.WriteAllText(claim, "{", Utf8);
        var broken = f.Client.Raw("start_operation", form); Check.True(broken["isError"].IsTrue()); Check.Contains("claim_record_unreadable", broken.ToJsonString());
        Check.Equal("{", File.ReadAllText(claim)); Check.Equal(0, Directory.GetFiles(f.Serve, "request.json", SearchOption.AllDirectories).Length);
    }

    [Case]
    private static void CorruptHistoryIsLoggedAndClaimTargetsDoNotFallBack()
    {
        using var f = new Fixture(); string unrelated = Path.Combine(f.Serve, Guid.NewGuid().ToString()); Directory.CreateDirectory(unrelated);
        string broken = Path.Combine(unrelated, "request.json"); File.WriteAllText(broken, "{", Utf8);
        var form = f.Form("location"); var first = f.Execute(form); Check.Equal("exited", first["state"].String());
        var events = File.ReadLines(f.FilePath("logs/server-events.jsonl")).Select(line => JsonNode.Parse(line).Object()).ToArray();
        Check.True(events.Any(item => item["kind"].Text() == "request_record_unreadable" && item["file"].Text() == broken)); Check.Equal("{", File.ReadAllText(broken));
        string target = Path.Combine(f.Serve, first["execution_id"].String(), "request.json"); File.WriteAllText(target, "{", Utf8);
        var result = f.Client.Raw("start_operation", form); Check.True(result["isError"].IsTrue()); Check.Contains("request_record_unreadable", result.ToJsonString());
        Check.Equal("{", File.ReadAllText(target));
    }

    [Case]
    private static void StartupFailureSidecarNeverOverridesExistingResult()
    {
        using var f = new Fixture(); string id = Guid.NewGuid().ToString(); string serve = Path.Combine(f.Serve, id); Directory.CreateDirectory(serve);
        WriteNew(Path.Combine(serve, "request.json"), new JsonObject { ["business"] = new JsonObject { ["cwd"] = f.DirectoryPath } });
        var query = new JsonObject { ["execution_id"] = id }; Check.Equal("unknown", f.Client.Call("status", query)["state"].String());
        string sidecar = Path.Combine(serve, "serve-error.json"); var failure = new JsonObject { ["state"] = "not_started", ["execution_id"] = null,
            ["error"] = new JsonObject { ["kind"] = "OSError", ["reason"] = "synthetic failure" } };
        WriteNew(sidecar, failure); Check.Equal("start_failed", f.Client.Call("status", query)["state"].String());
        foreach (string invalid in new[] { "{", "[]", "{}", "{\"state\":\"running\"}", "{\"state\":\"not_started\",\"error\":{\"kind\":\"OSError\",\"reason\":7}}" })
        { File.WriteAllText(sidecar, invalid, Utf8); Check.Equal("unknown", f.Client.Call("status", query)["state"].String()); }
        Save(sidecar, failure); string record = Path.Combine(f.DirectoryPath, ".codex-command-records", id); Directory.CreateDirectory(record);
        foreach (string state in new[] { "exited", "unknown" })
        {
            Save(Path.Combine(record, "result.json"), new JsonObject { ["state"] = state, ["execution_id"] = id, ["reason"] = "existing result" });
            var result = f.Client.Call("status", query); Check.Equal(state, result["state"].String()); Check.True(!result.ContainsKey("serve_error"));
        }
    }

    [Case]
    private static void HalfPublishedHistoryRemainsBlocked()
    {
        using var f = new Fixture(); var form = f.Form("location"); string fingerprint = Digest(form), id = Guid.NewGuid().ToString();
        string serve = Path.Combine(f.Serve, id); Directory.CreateDirectory(serve);
        WriteNew(Path.Combine(serve, "request.json"), new JsonObject { ["content_fingerprint"] = fingerprint, ["business"] = new JsonObject { ["cwd"] = f.DirectoryPath } });
        var blocked = f.Start(form); Check.Equal(id, blocked["execution_id"].String()); Check.True(blocked["dedup_blocked"].IsTrue());
        Check.True(!Directory.Exists(Path.Combine(f.DirectoryPath, ".codex-command-records", id)));
    }

    [Case]
    private static void WorkerRejectsMissingOrEmptyArgv()
    {
        foreach (var (input, reason) in new[] { ("{\"handshake\":\"job_assigned\"}\n", "array_required"), ("{\"handshake\":\"job_assigned\",\"argv\":[]}\n", "worker_argv_required") })
        {
            var result = Fixture.Run(TestRunner.Server, ["worker"], input); Check.Equal(125, result.Exit);
            var error = JsonNode.Parse(result.Error).Object(); Check.Equal("Invalid", error["kind"].String()); Check.Equal(reason, error["reason"].String());
        }
    }
}
