using System.Diagnostics;
using System.Text.Json.Nodes;
using static CommandEntry.RecordJson;

namespace CommandEntry;

internal sealed partial class ExecutionServer
{
    private JsonObject Status(JsonObject form)
    {
        form.Known(["execution_id"]);
        string id = form["execution_id"].String("execution_id_required"), directory = Locate(id);
        var failure = StartupFailureWithoutResult(id, directory);
        var state = ExecutionRecords.Snapshot(directory);
        if (failure is not null && !File.Exists(Path.Combine(directory, "result.json")))
            state = new() { ["state"] = "start_failed", ["serve_error"] = failure, ["subgoal"] = new JsonObject { ["status"] = "unknown" } };
        state["execution_id"] = id; return ExecutionRecords.Bounded(state);
    }

    private JsonObject Output(JsonObject form)
    {
        form.Known(["execution_id", "stream", "offset", "count"]);
        string id = form["execution_id"].String("execution_id_required"), directory = Locate(id);
        string stream = form.ContainsKey("stream") ? form["stream"].String("invalid_stream") : "stdout";
        Require(stream is "stdout" or "stderr", "invalid_stream");
        string path = Path.Combine(directory, stream + ".txt"); Require(File.Exists(path), "retained_output_unavailable");
        int offset = form.Int("offset", 0), count = form.Int("count", 2048);
        Require(offset >= 0, "invalid_offset"); Require(count is >= 1 and <= 4096, "output_count_range_1_4096");
        string text = File.ReadAllText(path, Utf8).Replace("\r\n", "\n").Replace('\r', '\n');
        int length = OutputCapture.Length(text); var state = ExecutionRecords.Snapshot(directory);
        return new() { ["execution_id"] = id, ["state"] = state["state"]?.Copy(), ["stream"] = stream,
            ["offset_characters"] = offset, ["text"] = OutputCapture.Slice(text, offset, count),
            ["next_offset"] = Math.Min((long)offset + count, length), ["retained_view_end"] = (long)offset + count >= length,
            ["metadata"] = state["output"]?[stream]?.Copy() };
    }

    private async Task<JsonObject> TerminateAndConfirm(JsonObject instance)
    {
        int? pid = instance["pid"] is null ? null : instance.Int("pid", 0);
        ulong? creation = instance["creation_time"] is null ? null : instance["creation_time"]!.GetValue<ulong>();
        if (pid is null || creation is null) return new() { ["terminated"] = false, ["confirmed_dead"] = false, ["reason"] = "instance_identity_missing" };
        var report = WindowsProcess.TerminateSameInstance(pid, creation); var elapsed = Stopwatch.StartNew();
        while (elapsed.Elapsed.TotalSeconds < policy.Int("cancel_confirm_seconds", 10))
        {
            var current = WindowsProcess.Observe(pid.Value);
            if (current["alive"]?.GetValue<bool>() == false || (current["creation_time"] is not null && current["creation_time"]!.GetValue<ulong>() != creation))
            { report["confirmed_dead"] = true; return report; }
            await Task.Delay(200);
        }
        report["confirmed_dead"] = false; return report;
    }

    private async Task<JsonObject> Cancel(JsonObject form)
    {
        form.Known(["execution_id"]);
        string id = form["execution_id"].String("execution_id_required"), directory = Locate(id);
        if (StartupFailureWithoutResult(id, directory) is not null)
            return new() { ["execution_id"] = id, ["state"] = "not_started", ["cancel_action"] = "already_terminal" };
        Require(File.Exists(Path.Combine(directory, "result.json")),
            "record_missing_unconfirmed: preserve the claim and request; manual recovery of the original evidence is required.");
        var state = ExecutionRecords.Snapshot(directory);
        if (ExecutionRecords.ConfirmedTerminal.Contains(state["state"].String()))
            return new() { ["execution_id"] = id, ["state"] = state["state"]?.Copy(), ["cancel_action"] = "already_terminal" };
        string path = Path.Combine(directory, "cancel-request.json"), action;
        try { WriteNew(path, new JsonObject { ["requested_at_unix"] = WindowsProcess.UnixNow, ["requested_by"] = "exec_server" }); action = "cancel_request_written"; }
        catch (IOException error) when ((error.HResult & 0xffff) is 80 or 183) { action = "cancel_request_already_present"; }
        var elapsed = Stopwatch.StartNew();
        while (elapsed.Elapsed.TotalSeconds < policy.Int("cancel_grace_seconds", 15))
        {
            string current = ExecutionRecords.Snapshot(directory)["state"].String();
            if (ExecutionRecords.ConfirmedTerminal.Contains(current))
                return new() { ["execution_id"] = id, ["state"] = current, ["cancel_action"] = action + "_and_finished_within_grace" };
            await Task.Delay(1000);
        }
        state = ExecutionRecords.Snapshot(directory);
        var detail = new JsonObject { ["owner"] = await TerminateAndConfirm(state["owner"] as JsonObject ?? new()) };
        if (state["worker"] is JsonObject worker && worker["pid"] is not null) detail["worker"] = await TerminateAndConfirm(worker);
        string birthFile = Path.Combine(directory, "business-process.json");
        if (File.Exists(birthFile)) detail["business"] = await TerminateAndConfirm(Read(birthFile));
        bool dead = detail.All(p => p.Value!["confirmed_dead"].IsTrue());
        var outcome = (JsonObject)detail.Copy(); outcome["checked_at_unix"] = WindowsProcess.UnixNow; outcome["all_known_processes_confirmed_dead"] = dead;
        Save(Path.Combine(directory, "cancel-outcome.json"), outcome);
        return new() { ["execution_id"] = id, ["state"] = ExecutionRecords.Snapshot(directory)["state"]?.Copy(), ["cancel_action"] = "hard_kill_after_grace",
            ["confirmed_dead"] = dead, ["detail"] = detail, ["note"] = "Record is not rewritten; unknown stays unknown. A new intent is allowed only when all known processes are confirmed dead." };
    }

    private async Task<JsonObject> Wait(JsonObject form)
    {
        form.Known(["execution_id"]);
        string id = form["execution_id"].String("execution_id_required"), directory = Locate(id);
        if (!File.Exists(Path.Combine(directory, "result.json")))
        {
            var result = Status(form);
            result["wait_outcome"] = result["state"].Text() == "start_failed" ? "terminal" : "unconfirmed";
            if (result["wait_outcome"].Text() == "unconfirmed")
                result["note"] = "Execution record is missing; manual recovery of the original evidence is required. Process liveness is unknown.";
            return result;
        }
        int budget = policy["wait_budget_seconds"]!.GetValue<int>();
        int interval = policy["wait_poll_interval_seconds"]!.GetValue<int>();
        int threshold = policy["wait_stop_after_no_progress"]!.GetValue<int>();
        var elapsed = Stopwatch.StartNew();
        FileMutex mutex;
        try { mutex = new FileMutex(Path.Combine(directory, "wait-state.lock")); }
        catch (IOException error) when ((error.HResult & 0xffff) is 32 or 33)
        { throw new InvalidRequest("wait_in_progress_retry_later"); }
        using var heldWait = mutex;
        string file = Path.Combine(directory, "wait-state.json");
        var journal = File.Exists(file) ? Read(file) : new JsonObject { ["count"] = 0, ["previous"] = null };
        JsonObject? observed = null;
        while (true)
        {
            var state = ExecutionRecords.Snapshot(directory);
            if (ExecutionRecords.Terminal.Contains(state["state"].String()))
            {
                var result = ExecutionRecords.Bounded(state);
                bool confirmed = ExecutionRecords.ConfirmedTerminal.Contains(state["state"].String());
                result["wait_outcome"] = confirmed ? "terminal" : "unconfirmed";
                if (!confirmed) result["note"] = "Process termination is unconfirmed. Use cancel to confirm whether all known process instances are dead.";
                return result;
            }
            var current = ExecutionRecords.Collect(directory, state);
            if (journal["previous"] is JsonObject previous)
            {
                observed = ExecutionRecords.Progress(previous, current);
                journal["count"] = observed["progress_confirmed"].IsTrue() ? 0 : journal.Int("count", 0) + 1;
                journal["previous"] = current; Save(file, journal);
                if (journal.Int("count", 0) >= threshold)
                    return new() { ["execution_id"] = id, ["state"] = state["state"]?.Copy(), ["wait_outcome"] = "stop_automatic_wait",
                        ["no_progress_count"] = journal["count"]?.Copy(), ["no_progress_threshold"] = threshold, ["observation"] = observed,
                        ["note"] = "Consecutive observations without progress reached the policy threshold (wait_stop_after_no_progress)." };
            }
            else { journal["previous"] = current; Save(file, journal); }
            double remaining = budget - elapsed.Elapsed.TotalSeconds;
            if (remaining <= 0) return new() { ["execution_id"] = id, ["state"] = state["state"]?.Copy(), ["wait_outcome"] = "budget_exhausted",
                ["suggest_poll_seconds"] = interval, ["observation"] = observed };
            await Task.Delay(TimeSpan.FromSeconds(Math.Min(interval, remaining)));
        }
    }
}
