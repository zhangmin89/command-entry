using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using static CommandEntry.RecordJson;

namespace CommandEntry;

internal sealed partial class ExecutionServer
{
    private readonly string policyPath, policyHash, serveRoot, logRoot;
    private readonly JsonObject policy;
    private readonly uint spawnFlags;
    private readonly bool orphanGuaranteed;
    private readonly SemaphoreSlim calls = new(1, 1);

    internal ExecutionServer(string policyPath, string? bindingPath)
    {
        this.policyPath = BusinessPaths.Resolve(policyPath, "file");
        using (var locks = new FileBindings())
        {
            locks.Add(this.policyPath); policy = Read(this.policyPath);
            Require(policy.Int("version", 0) == 2, "policy_version_required");
            policyHash = locks.Bindings[this.policyPath].String();
            if (bindingPath is not null) VerifyBinding(bindingPath);
        }
        serveRoot = BusinessPaths.Resolve(policy["serve_root"].String()); Directory.CreateDirectory(serveRoot);
        logRoot = BusinessPaths.Resolve(policy["log_root"].Text() ?? Path.Combine(Path.GetDirectoryName(this.policyPath)!, "logs"));
        (spawnFlags, orphanGuaranteed) = OwnerLauncher.Flags();
        var missing = new JsonArray(); bool dotnet = false;
        foreach (var pair in policy.ObjectOrEmpty("programs"))
        {
            string path = pair.Value!["path"].Text() ?? "";
            if (!File.Exists(path)) missing.Add((JsonNode)(pair.Key));
            dotnet |= pair.Value["kind"].Text() == "native" && Path.GetFileName(path).Equals("dotnet.exe", StringComparison.OrdinalIgnoreCase);
        }
        Log("startup", new() { ["flags"] = "0x" + spawnFlags.ToString("x"), ["orphan_guaranteed"] = orphanGuaranteed,
            ["program_health"] = new JsonObject { ["missing"] = missing, ["healed"] = new JsonArray(),
                ["missing_env"] = dotnet && string.IsNullOrEmpty(Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE")) ? new JsonArray("PROCESSOR_ARCHITECTURE") : new JsonArray() } });
    }

    private void VerifyBinding(string path)
    {
        var binding = Read(path);
        Require(binding.Int("schema_version", 0) == 2, "binding_version_required");
        Require(BusinessPaths.Resolve(binding["policy"]!["path"].String()).Equals(policyPath, StringComparison.OrdinalIgnoreCase), "binding_policy_path_mismatch");
        Require(policyHash == binding["policy"]!["sha256"].Text(), "policy_changed_since_review");
        foreach (var item in binding["runtime_files"].Array())
            Require(FileHash(item!["path"].String()) == item["sha256"].Text(), "runtime_changed_since_review_" + Path.GetFileName(item["path"].String()));
    }

    private void Log(string kind, JsonObject? fields = null)
    {
        try
        {
            Directory.CreateDirectory(logRoot);
            fields ??= new(); fields["kind"] = kind; fields["ts"] = WindowsProcess.UnixNow;
            File.AppendAllText(Path.Combine(logRoot, "server-events.jsonl"), Utf8.GetString(Packed(fields)) + '\n', Utf8);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException) { /* Diagnostics do not break serving. */ }
    }

    private JsonObject ReadRequest(string path)
    {
        try { return Read(path); }
        catch (Exception error) when (ExecutionRecords.Handled(error))
        { throw new InvalidRequest("request_record_unreadable: " + path + " (" + ExecutionRecords.ErrorKind(error) + ")"); }
    }

    private IEnumerable<(string Path, JsonObject Envelope)> History(bool strict = false)
    {
        foreach (string directory in Directory.EnumerateDirectories(serveRoot))
        {
            string path = Path.Combine(directory, "request.json");
            if (!File.Exists(path)) continue;
            JsonObject envelope;
            try
            {
                envelope = ReadRequest(path);
                if (strict) Require(envelope["content_fingerprint"].Text() is { Length: > 0 }, "request_fingerprint_missing: " + path);
            }
            catch (InvalidRequest error)
            {
                Log("request_record_unreadable", new() { ["file"] = path, ["reason"] = error.Message });
                if (strict) throw;
                continue;
            }
            yield return (path, envelope);
        }
    }

    private string? Find(string fingerprint, bool strict = false) => History(strict)
        .Where(p => p.Envelope["content_fingerprint"].Text() == fingerprint)
        .OrderByDescending(p => File.GetLastWriteTimeUtc(p.Path)).Select(p => Path.GetFileName(Path.GetDirectoryName(p.Path))).FirstOrDefault();

    private string Locate(string id)
    {
        Require(JsonFields.IsUuid(id), "execution_id_required");
        string entry = Path.Combine(serveRoot, id, "request.json"); Require(File.Exists(entry), "execution_not_found");
        string cwd = BusinessPaths.Resolve(ReadRequest(entry)["business"]!["cwd"].String());
        return Path.Combine(BusinessPaths.Context(policy, cwd), id);
    }

    private static bool Abandoned(string record)
    {
        try { return Read(Path.Combine(record, "cancel-outcome.json"))["all_known_processes_confirmed_dead"].IsTrue(); }
        catch (Exception error) when (ExecutionRecords.Handled(error)) { return false; }
    }

    private JsonObject? StartupFailure(string id)
    {
        JsonObject failure;
        try { failure = Read(Path.Combine(serveRoot, id, "serve-error.json")); }
        catch (Exception error) when (ExecutionRecords.Handled(error)) { return null; }
        if (failure["state"].Text() != "not_started" || (failure["execution_id"] is not null && failure["execution_id"].Text() != id)) return null;
        if (failure["error"] is not JsonObject detail || detail["kind"].Text() is null || detail["reason"].Text() is null) return null;
        return failure;
    }

    internal async Task<JsonObject> Dispatch(string name, JsonObject form)
    {
        await calls.WaitAsync();
        try
        {
            JsonObject result = name switch
            {
                "start_operation" => await Start(form["business"] as JsonObject ?? form),
                "status" => Status(form), "output" => Output(form), "cancel" => await Cancel(form),
                "wait" => await Wait(form), "read_text" => TextRangeReader.Read(form, policy),
                _ => throw new InvalidRequest("unknown_tool")
            };
            Log(name); return result;
        }
        catch (Exception error) when (ExecutionRecords.Handled(error))
        {
            Log("rejected", new() { ["tool"] = name, ["error_kind"] = ExecutionRecords.ErrorKind(error),
                ["reason"] = error is InvalidRequest ? error.Message.Split(':')[0][..Math.Min(80, error.Message.Split(':')[0].Length)] : ExecutionRecords.ErrorKind(error) });
            throw;
        }
        finally { calls.Release(); }
    }

    private string? ClaimIdentity(string fingerprint, string claimPath)
    {
        if (!File.Exists(claimPath))
        {
            string? found = Find(fingerprint);
            if (found is not null) Save(claimPath, new JsonObject { ["execution_id"] = found, ["healed_at_unix"] = WindowsProcess.UnixNow });
            return found;
        }
        try
        {
            string? claimed = Read(claimPath)["execution_id"].Text();
            Require(JsonFields.IsUuid(claimed), "claim_execution_id_required");
            return claimed;
        }
        catch (Exception error) when (error is JsonException or InvalidRequest or InvalidOperationException)
        {
            Log("claim_record_unreadable", new() { ["file"] = claimPath, ["reason"] = ExecutionRecords.ErrorKind(error) });
            try
            {
                string? found = Find(fingerprint, strict: true);
                Require(found is not null, "claim_recovery_identity_missing"); Require(JsonFields.IsUuid(found), "claim_execution_id_required");
                Save(claimPath, new JsonObject { ["execution_id"] = found, ["healed_at_unix"] = WindowsProcess.UnixNow });
                return found;
            }
            catch (Exception recovery) when (ExecutionRecords.Handled(recovery))
            { throw new InvalidRequest("claim_record_unreadable: " + claimPath + " (recovery failed: " + recovery.Message + ")"); }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        { throw new InvalidRequest("claim_record_unreadable: " + claimPath + " (" + ExecutionRecords.ErrorKind(error) + ")"); }
    }

    private JsonObject Existing(string id, bool collision = false)
    {
        string directory = Locate(id);
        var state = Directory.Exists(directory) ? ExecutionRecords.Snapshot(directory) : new JsonObject { ["state"] = "unknown", ["reason"] = "record_missing" };
        string name = state["state"].String();
        bool blocked = collision ? !ExecutionRecords.ConfirmedTerminal.Contains(name) && !Abandoned(directory) : name is "unknown" or "tool_error";
        return new() { ["execution_id"] = id, ["state"] = name, ["in_flight_dedup"] = !blocked, ["dedup_blocked"] = blocked,
            ["orphan_guaranteed"] = orphanGuaranteed, ["record_dir"] = directory,
            ["note"] = blocked ? "Instance state is unconfirmed; a duplicate is NOT started. Use cancel to confirm abandonment before a new intent." : "Same content still running; returning the existing id." };
    }

    private async Task<JsonObject> Start(JsonObject form)
    {
        form.Known(RequestShape.StartFields);
        string operation = form["operation"].String("unsupported_operation");
        Require(operation is "native" or "script" or "python_unittest", "unsupported_operation");
        string workdir = form["workdir"].String("workdir_required"), cwd = BusinessPaths.Resolve(workdir, "directory");
        _ = BusinessPaths.Context(policy, cwd);
        string program = form["program"].String("program_not_configured");
        Require(policy.ObjectOrEmpty("programs").ContainsKey(program), "program_not_configured");
        _ = form.ArrayOrEmpty("args"); var options = RequestShape.Options(form, policy);
        var content = new JsonObject(form.Where(p => p.Key != "previous_execution" && !RequestShape.ExecutionKeys.Contains(p.Key) && p.Value is not null).Select(p => KeyValuePair.Create(p.Key, p.Value?.Copy())));
        content["args"] ??= new JsonArray(); content["workdir"] = cwd;
        string fingerprint = Digest(content);
        byte[] policyBytes = File.ReadAllBytes(policyPath);
        Require(Hash(policyBytes) == policyHash, "policy_changed_since_review");
        var snapshot = JsonNode.Parse(Utf8.GetString(policyBytes).TrimStart('\ufeff')).Object();
        string claimDirectory = Path.Combine(serveRoot, "_claims", fingerprint); Directory.CreateDirectory(claimDirectory);
        FileMutex mutex;
        try { mutex = new(Path.Combine(claimDirectory, "claim.lock")); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException) { throw new InvalidRequest("claim_pending_unconfirmed_retry_later"); }
        string id, requestId, inputDirectory;
        using (mutex)
        {
            string claimPath = Path.Combine(claimDirectory, "claim.json");
            string? existing = ClaimIdentity(fingerprint, claimPath);
            if (existing is not null)
            {
                string record = Locate(existing); string name = ExecutionRecords.Snapshot(record)["state"].String();
                bool notStarted = !Directory.Exists(record) && File.Exists(Path.Combine(serveRoot, existing, "serve-error.json"));
                if (!notStarted && !ExecutionRecords.ConfirmedTerminal.Contains(name) && !Abandoned(record)) return Existing(existing);
            }
            string task = "mcp-direct", step; string? previousRequest = null; long attempt = 0;
            if (form.ContainsKey("previous_execution"))
            {
                string previousId = form["previous_execution"].String("execution_id_required"); Require(JsonFields.IsUuid(previousId), "execution_id_required");
                string previousPath = Path.Combine(serveRoot, previousId, "request.json"); Require(File.Exists(previousPath), "previous_execution_not_found");
                var previousEnvelope = ReadRequest(previousPath); var origin = RequestShape.Shape(previousEnvelope["business"].Object());
                Require(previousEnvelope["content_fingerprint"].Text() == fingerprint, "previous_execution_content_mismatch");
                Require(ExecutionRecords.ConfirmedTerminal.Contains(ExecutionRecords.Snapshot(Locate(previousId))["state"].String()), "previous_attempt_not_confirmed_terminal");
                task = origin["task_ref"].String(); step = origin["step_ref"].String(); previousRequest = origin["request_id"].String(); attempt = origin["attempt"].Integer("invalid_attempt") + 1;
            }
            else step = fingerprint[..12] + "-" + (1 + History().Count(p => p.Envelope["content_fingerprint"].Text() == fingerprint));
            var business = new JsonObject(form.Where(p => p.Key is not "workdir" and not "previous_execution").Select(p => KeyValuePair.Create(p.Key, p.Value?.Copy())));
            business["task_ref"] = task; business["step_ref"] = step; business["attempt"] = attempt; business["cwd"] = workdir;
            foreach (var option in options) business[option.Key] = option.Value?.Copy();
            if (previousRequest is not null) business["previous_request"] = previousRequest;
            var request = RequestShape.Shape(business); requestId = request["request_id"].String(); id = ExecutionId(requestId);
            Require(!policy["require_orphan_guarantee"].IsTrue() || orphanGuaranteed, "orphan_guarantee_required_but_unavailable");
            inputDirectory = Path.Combine(serveRoot, id);
            if (!DirectoryCreation.TryCreateNew(inputDirectory))
            {
                string? rival = Find(fingerprint); Require(rival is not null, "serve_dir_collision_without_match: " + inputDirectory);
                Save(claimPath, new JsonObject { ["execution_id"] = rival, ["republished_at_unix"] = WindowsProcess.UnixNow });
                return Existing(rival!, collision: true);
            }
            var envelope = new JsonObject { ["schema_version"] = 2, ["business"] = business, ["fingerprint"] = RequestDigest(request), ["content_fingerprint"] = fingerprint };
            string publication = Path.Combine(inputDirectory, "request.json");
            try
            {
                WriteNew(publication, envelope); publication = Path.Combine(inputDirectory, "policy.json"); WriteNew(publication, snapshot);
                publication = claimPath; Save(publication, new JsonObject { ["execution_id"] = id, ["published_at_unix"] = WindowsProcess.UnixNow });
            }
            catch (Exception error) when (ExecutionRecords.Handled(error))
            {
                Save(Path.Combine(inputDirectory, "request.json"), envelope);
                var detail = ExecutionRecords.Error(error); detail["reason"] = publication + ": " + detail["reason"].String();
                WriteNew(Path.Combine(inputDirectory, "serve-error.json"), new JsonObject { ["schema_version"] = 2, ["state"] = "not_started", ["execution_id"] = id, ["error"] = detail.Copy() });
                return StartResult(id, requestId, cwd, "start_failed", new JsonObject { ["error"] = detail }, "Input publication failed before spawning; the failure is queryable via status.");
            }
        }
        try { OwnerLauncher.Start(inputDirectory, cwd, spawnFlags); }
        catch (Exception error) when (ExecutionRecords.Handled(error))
        {
            var detail = ExecutionRecords.Error(error);
            WriteNew(Path.Combine(inputDirectory, "serve-error.json"), new JsonObject { ["schema_version"] = 2, ["state"] = "not_started", ["execution_id"] = id, ["error"] = detail.Copy() });
            return StartResult(id, requestId, cwd, "start_failed", new JsonObject { ["error"] = detail }, "Entry child could not be spawned; the failure is queryable via status.");
        }
        string resultPath = Path.Combine(BusinessPaths.Context(policy, cwd), id, "result.json");
        var elapsed = Stopwatch.StartNew();
        while (!File.Exists(resultPath) && elapsed.Elapsed.TotalSeconds < policy.Int("start_confirm_seconds", 15)) await Task.Delay(100);
        if (!File.Exists(resultPath))
        {
            var failure = StartupFailure(id);
            return StartResult(id, requestId, cwd, failure is null ? "unconfirmed_start" : "start_failed", failure,
                failure is null ? "Entry child did not confirm its initial state. Do NOT rerun blindly; query status for this execution_id first." : "Entry child reported a recorded startup failure.");
        }
        return StartResult(id, requestId, cwd, "starting", null, "Spawned detached entry child; query status/wait for the outcome.");
    }

    private JsonObject StartResult(string id, string requestId, string cwd, string state, JsonObject? failure, string note)
    {
        var result = new JsonObject { ["execution_id"] = id, ["request_id"] = requestId, ["state"] = state, ["in_flight_dedup"] = false,
            ["orphan_guaranteed"] = orphanGuaranteed, ["record_dir"] = Path.Combine(BusinessPaths.Context(policy, cwd), id), ["note"] = note };
        if (state != "starting") result["serve_error"] = failure;
        return result;
    }
}
