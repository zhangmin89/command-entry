using System.Diagnostics;
using System.Text.Json.Nodes;
using static CommandEntry.RecordJson;

namespace CommandEntry;

internal static class ExecutionOwner
{
    internal static string Executable => Path.Combine(AppContext.BaseDirectory, "CommandEntry.exe");
    internal static async Task<int> Serve(string inputDirectory)
    {
        try
        {
            var result = await Run(Path.Combine(inputDirectory, "request.json"), Path.Combine(inputDirectory, "policy.json"));
            return result["state"].Text() is "exited" or "running" or "starting" or "cancel_requested" or "cleaning" ? 0 : 125;
        }
        catch (Exception error) when (ExecutionRecords.Handled(error))
        {
            WriteNew(Path.Combine(inputDirectory, "serve-error.json"), new JsonObject
            {
                ["version"] = RecordJson.Version, ["state"] = "not_started", ["execution_id"] = null,
                ["subgoal"] = new JsonObject { ["status"] = "unknown" }, ["error"] = ExecutionRecords.Error(error)
            });
            return 125;
        }
    }

    internal static JsonObject Location()
    {
        string cwd = BusinessPaths.Resolve(Environment.CurrentDirectory, "directory"); BusinessPaths.CheckCwd(cwd);
        return new() { ["version"] = RecordJson.Version, ["operation"] = "location", ["cwd"] = cwd, ["state"] = "exited",
            ["process"] = new JsonObject { ["exit_code"] = 0, ["exit_code_source"] = "fixed_location_operation" },
            ["subgoal"] = new JsonObject { ["status"] = "confirmed", ["evidence"] = "actual process cwd and unchanged root/home exclusions" },
            ["persistence"] = new JsonObject { ["durable"] = false, ["result_readable_now"] = true, ["cross_session_retrieval"] = false } };
    }

    internal static async Task<JsonObject> Run(string requestPath, string policyPath)
    {
        var elapsed = Stopwatch.StartNew();
        using var locks = new FileBindings();
        locks.Add(requestPath);
        var envelope = Read(requestPath); var request = RequestShape.Shape(envelope["business"].Object());
        Require(MatchesRequest(envelope["fingerprint"].Text(), request), "prepared_request_content_conflict");
        if (request["operation"].Text() == "location") return Location();
        string cwd = BusinessPaths.Resolve(request["cwd"].String(), "directory"); BusinessPaths.CheckCwd(cwd);
        locks.Add(policyPath); var policy = Read(policyPath);
        Require(policy.Int("version", 0) == 3, "policy_version_required");
        string root = BusinessPaths.Context(policy, cwd), identity = ExecutionId(request["request_id"].String());
        string directory = Path.Combine(root, identity);
        Directory.CreateDirectory(root);
        if (!DirectoryCreation.TryCreateNew(directory))
        {
            var old = ExecutionRecords.Snapshot(directory);
            if (old["reason"].Text() == "claim_exists_without_readable_state")
            { old["request_id"] = request["request_id"]?.Copy(); old["duplicate_delivery"] = true; return old; }
            Require(MatchesRequest(old["request_fingerprint"].Text(), request), "request_identity_content_conflict");
            foreach (var pair in old.ObjectOrEmpty("bindings"))
            {
                if (pair.Key == Path.GetFullPath(requestPath) || pair.Key == Path.GetFullPath(policyPath) || pair.Key.EndsWith("powershell-invocation.json", StringComparison.Ordinal)) continue;
                Require(File.Exists(pair.Key) && FileHash(pair.Key) == pair.Value.Text(), "bound_file_changed_for_existing_identity");
            }
            old["duplicate_delivery"] = true; return ExecutionRecords.Bounded(old);
        }
        var result = new JsonObject
        {
            ["version"] = RecordJson.Version, ["execution_id"] = identity, ["request_id"] = request["request_id"]?.Copy(),
            ["logical_id"] = request["logical_id"]?.Copy(), ["request_fingerprint"] = RequestDigest(request), ["state"] = "not_started",
            ["cwd"] = cwd, ["record_dir"] = directory, ["request"] = request.Copy(), ["owner"] = WindowsProcess.Observe(Environment.ProcessId),
            ["process"] = new JsonObject { ["exit_code"] = null, ["exit_code_source"] = null }, ["subgoal"] = new JsonObject { ["status"] = "unknown" },
            ["persistence"] = new JsonObject { ["durable"] = true, ["result_readable_now"] = true, ["cross_session_retrieval"] = true },
            ["started_at_unix"] = WindowsProcess.UnixNow, ["last_observed_unix"] = WindowsProcess.UnixNow
        };
        var sources = new JsonObject();
        foreach (string file in Directory.EnumerateFiles(AppContext.BaseDirectory).Where(f => Path.GetExtension(f) is ".exe" or ".dll"))
            sources[Path.GetFileName(file)] = FileHash(file);
        result["source_fingerprint"] = Digest(sources);
        var inputs = new JsonObject();
        foreach (var input in request.ArrayOrEmpty("input_paths").Concat(request.ArrayOrEmpty("required_tools")))
            inputs[BusinessPaths.Resolve(input.String())] = new JsonObject { ["exists"] = File.Exists(input.String()) };
        result["input_observations"] = inputs;
        string resultPath = Path.Combine(directory, "result.json"); Save(resultPath, result);
        WindowsProcess.Job? job = null; Process? host = null;
        var captures = new Dictionary<string, OutputCapture>(); var drains = new List<Task>();
        object gate = new();
        using var finished = new CancellationTokenSource();
        Task? monitor = null, timer = null;
        void Persist()
        {
            result["last_observed_unix"] = WindowsProcess.UnixNow; result["elapsed_seconds"] = elapsed.Elapsed.TotalSeconds;
            result["output"] = new JsonObject(captures.Select(p => KeyValuePair.Create<string, JsonNode?>(p.Key, p.Value.Metadata())));
            Save(resultPath, result);
        }
        void Stop(string reason)
        {
            lock (gate)
            {
                if (finished.IsCancellationRequested) return;
                result["stop_reason"] = reason; result["state"] = "cleaning";
                try { Persist(); } finally { job?.Dispose(); }
            }
        }
        async Task TimeoutAfter(int seconds)
        {
            try { await Task.Delay(TimeSpan.FromSeconds(seconds), finished.Token); Stop("timed_out"); }
            catch (OperationCanceledException) when (finished.IsCancellationRequested) { }
        }
        async Task Monitor()
        {
            try
            {
                while (true)
                {
                    await Task.Delay(TimeSpan.FromSeconds(10), finished.Token);
                    if (File.Exists(Path.Combine(directory, "cancel-request.json"))) { Stop("cancelled"); return; }
                    lock (gate)
                    {
                        result["owner_observation"] = WindowsProcess.Observe(Environment.ProcessId);
                        var observations = ExecutionRecords.Collect(directory, result);
                        result["business_observation"] = observations["business_observation"]?.Copy();
                        result["artifact_observations"] = observations["artifact_observations"]?.Copy();
                        try { Persist(); }
                        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
                        { result["state"] = "unknown"; result["reason"] = "mandatory_state_write_failed"; job?.Dispose(); return; }
                    }
                }
            }
            catch (OperationCanceledException) when (finished.IsCancellationRequested) { }
        }
        async Task Execute()
        {
            var plan = await ExecutionPlan.Create(request, policy, locks, directory);
            result["argv"] = new JsonArray(new[] { plan.Executable }.Concat(plan.Arguments).Select(a => (JsonNode?)JsonValue.Create(a)).ToArray());
            result["bindings"] = locks.Bindings.Copy(); result["syntax"] = plan.Syntax;
            result["run_budget_seconds"] = plan.Budget; result["output_quota_bytes"] = plan.OutputQuota;
            if (request["attempt"].Integer("invalid_attempt") > 0)
            {
                var previous = ExecutionRecords.Snapshot(Path.Combine(root, ExecutionId(request["previous_request"].String())));
                Require(previous["logical_id"].Text() == request["logical_id"].Text() && ExecutionRecords.ConfirmedTerminal.Contains(previous["state"].String()), "previous_attempt_not_confirmed_terminal");
                var bindings = previous.ObjectOrEmpty("bindings");
                var changed = locks.Bindings.Where(p => bindings.ContainsKey(p.Key) && p.Key != Path.GetFullPath(requestPath) && p.Key != Path.GetFullPath(policyPath) && p.Value.Text() != bindings[p.Key].Text())
                    .Select(p => (JsonNode?)JsonValue.Create(p.Key)).ToArray();
                Require(changed.Length > 0, "verified_changed_conditions_required_for_new_attempt");
                Require(JsonNode.DeepEquals(previous["request"].Object().ArrayOrEmpty("acceptance"), request.ArrayOrEmpty("acceptance")) &&
                    JsonNode.DeepEquals(previous["request"].Object().ObjectOrEmpty("artifacts"), request.ObjectOrEmpty("artifacts")), "original_acceptance_must_be_preserved");
                result["changed_conditions"] = new JsonArray(changed);
            }
            result["state"] = "starting"; Persist();
            job = new();
            host = Process.Start(WindowsProcess.StartInfo(Executable, ["worker"], cwd))!;
            job.Assign(host);
            foreach (var (name, stream) in new[] { ("stdout", host.StandardOutput.BaseStream), ("stderr", host.StandardError.BaseStream) })
            {
                var capture = new OutputCapture(Path.Combine(directory, name + ".txt"), request["encoding"].Text() ?? "utf-8", plan.OutputQuota);
                captures[name] = capture; drains.Add(capture.DrainAsync(stream));
            }
            result["state"] = "running"; result["worker"] = WindowsProcess.Observe(host.Id); Persist();
            var message = new JsonObject { ["handshake"] = "job_assigned", ["argv"] = result["argv"]?.Copy(), ["cwd"] = cwd,
                ["record_dir"] = directory, ["stdin_file"] = request["stdin_file"]?.Copy(), ["powershell_request"] = plan.PowerShellRequest };
            await host.StandardInput.BaseStream.WriteAsync(Packed(message)); await host.StandardInput.BaseStream.WriteAsync(new byte[] { 10 });
            host.StandardInput.Close(); timer = TimeoutAfter(plan.Budget); monitor = Monitor();
            await host.WaitForExitAsync(); finished.Cancel(); job.Dispose();
            if (monitor is not null) await monitor;
            if (timer is not null) await timer;
            try { await Task.WhenAll(drains).WaitAsync(TimeSpan.FromSeconds(policy.Int("cleanup_seconds", 10))); }
            catch (TimeoutException) { /* capture_complete remains false in the persisted metadata. */ }
            if (result["reason"].Text() != "mandatory_state_write_failed") result["state"] = result["stop_reason"]?.Copy() ?? JsonValue.Create("exited");
            result["process"] = new JsonObject { ["exit_code"] = host.ExitCode, ["exit_code_source"] = result["stop_reason"] is null ? "worker_propagated_business_process" : "terminated_worker", ["worker_pid"] = host.Id };
            string birth = Path.Combine(directory, "business-process.json");
            if (File.Exists(birth))
            { result["business_start"] = Read(birth); result["business_observation"] = WindowsProcess.Observe(result["business_start"]!.AsObject().Int("pid", 0)); }
            else { result["state"] = "unknown"; result["reason"] = "business_start_record_missing"; result["process"]!["exit_code_source"] = "worker_without_confirmed_business_start"; }
            result["worker_observation"] = WindowsProcess.Observe(host.Id);
            var codes = policy["operations"]![request["operation"].String()]?["acceptable_exit_codes"] as JsonArray ?? new JsonArray(0);
            result["operation_result"] = new JsonObject { ["acceptable_exit"] = result["state"].Text() == "exited" ? codes.Any(c => c.Integer("invalid_exit_code") == host.ExitCode) : null };
            result["subgoal"] = result["state"].Text() == "exited" ? ExecutionRecords.Acceptance(request) : new JsonObject { ["status"] = "unknown" };
        }
        async Task Fail(Exception error)
        {
            result["state"] = host is null ? "rejected" : "tool_error"; result["error"] = ExecutionRecords.Error(error); result["bindings"] = locks.Bindings.Copy();
            await ExecutionCleanup.PersistFailure(result, async () =>
            {
                finished.Cancel(); job?.Dispose();
                if (monitor is not null) await monitor;
                if (timer is not null) await timer;
                if (host is not null) { await host.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(policy.Int("cleanup_seconds", 10))); result["process"]!["exit_code"] = host.ExitCode; }
            }, Persist);
        }
        try { await ExecutionCleanup.Complete(Execute, Fail, Persist); }
        finally
        {
            finished.Cancel(); job?.Dispose(); host?.Dispose();
            foreach (var capture in captures.Values) capture.Dispose();
        }
        return ExecutionRecords.Bounded(result);
    }
}
