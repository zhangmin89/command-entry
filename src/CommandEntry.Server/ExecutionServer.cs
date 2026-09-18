using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using static CommandEntry.RecordJson;

namespace CommandEntry;

internal sealed partial class ExecutionServer
{
    private readonly string policyPath, policyHash, serveRoot, logRoot, logMutexName;
    private readonly JsonObject policy;
    private readonly uint spawnFlags;
    private readonly bool orphanGuaranteed;
    private readonly SemaphoreSlim calls = new(1, 1);
    private readonly PublicationIndex publications;

    internal string[] ProgramKeys => policy.ObjectOrEmpty("programs").Select(pair => pair.Key).Order(StringComparer.Ordinal).ToArray();

    internal ExecutionServer(string policyPath, string? bindingPath)
    {
        this.policyPath = BusinessPaths.Resolve(policyPath, "file");
        using (var locks = new FileBindings())
        {
            locks.Add(this.policyPath); policy = Read(this.policyPath);
            Require(policy.Int("version", 0) == 3, "policy_version_required");
            policyHash = locks.Bindings[this.policyPath].String();
            if (bindingPath is not null) VerifyBinding(bindingPath);
            var waitProblems = PolicyValidator.ValidateWaitSettings(policy);
            Require(waitProblems.Count == 0, "Invalid wait policy: " + Utf8.GetString(Packed(waitProblems)));
        }
        serveRoot = BusinessPaths.Resolve(policy["serve_root"].String()); Directory.CreateDirectory(serveRoot);
        publications = new(serveRoot);
        logRoot = BusinessPaths.Resolve(policy["log_root"].Text() ?? Path.Combine(Path.GetDirectoryName(this.policyPath)!, "logs"));
        logMutexName = @"Global\CommandEntry.ServerEvents." + Hash(Utf8.GetBytes(logRoot.ToUpperInvariant()));
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

    [System.Diagnostics.CodeAnalysis.UnconditionalSuppressMessage("SingleFile", "IL3000",
        Justification = "Native AOT intentionally has no assembly file; a managed apphost must bind its separate assembly and configuration.")]
    private void VerifyBinding(string path)
    {
        var binding = Read(path);
        Require(binding.Int("schema_version", 0) == 2, "binding_version_required");
        Require(BusinessPaths.Resolve(binding["policy"]!["path"].String()).Equals(policyPath, StringComparison.OrdinalIgnoreCase), "binding_policy_path_mismatch");
        Require(policyHash == binding["policy"]!["sha256"].Text(), "policy_changed_since_review");
        using var locks = new FileBindings();
        var verified = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in binding["runtime_files"].Array())
        {
            string file = BusinessPaths.Resolve(item!["path"].String(), "file");
            locks.Add(file);
            Require(locks.Bindings[file].Text() == item["sha256"].Text(), "runtime_changed_since_review_" + Path.GetFileName(file));
            verified.Add(file);
        }
        string[] names = BindingBuilder.RuntimeNames(typeof(ExecutionServer).Assembly.Location.Length > 0);
        foreach (string file in names.Select(name => Path.Combine(AppContext.BaseDirectory, name))
            .Append(Environment.ProcessPath ?? throw new InvalidRequest("process_path_unavailable")))
            Require(verified.Contains(BusinessPaths.Resolve(file, "file")), "runtime_binding_missing_" + Path.GetFileName(file));
    }

    private void Log(string kind, JsonObject? fields = null)
    {
        try
        {
            Directory.CreateDirectory(logRoot);
            fields ??= new(); fields["kind"] = kind; fields["ts"] = WindowsProcess.UnixNow;
            using var mutex = new Mutex(false, logMutexName);
            try { if (!mutex.WaitOne(TimeSpan.FromSeconds(2))) return; }
            catch (AbandonedMutexException) { /* Ownership transfers when a previous writer exits. */ }
            try { File.AppendAllText(Path.Combine(logRoot, "server-events.jsonl"), Utf8.GetString(Packed(fields)) + '\n', Utf8); }
            finally { mutex.ReleaseMutex(); }
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

    private JsonObject? StartupFailureWithoutResult(string id, string directory)
    {
        string result = Path.Combine(directory, "result.json");
        if (File.Exists(result)) return null;
        var failure = StartupFailure(id);
        return File.Exists(result) ? null : failure;
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
            Log(name, name == "start_operation" ? new JsonObject
            {
                ["dedup"] = result["in_flight_dedup"]?.Copy(),
                ["retry"] = (form["business"] as JsonObject ?? form)["previous_execution"].Text() is { Length: > 0 }
            } : null);
            return result;
        }
        catch (Exception error) when (ExecutionRecords.Handled(error))
        {
            Log("rejected", RejectionAudit.Record(logRoot, name, form, error));
            throw;
        }
        finally { calls.Release(); }
    }

    private string? ClaimIdentity(string fingerprint, string claimPath, PublicationIndex.Session index)
    {
        if (!File.Exists(claimPath))
        {
            string? found = index.Latest(fingerprint);
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
                Require(index.Latest(fingerprint) is null || index.Latest(fingerprint) == found,
                    "claim_index_mismatch: preserve evidence for manual recovery");
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
        var state = File.Exists(Path.Combine(directory, "result.json")) ? ExecutionRecords.Snapshot(directory) : new JsonObject { ["state"] = "unknown", ["reason"] = "record_missing" };
        string name = state["state"].String();
        bool blocked = collision ? !ExecutionRecords.ConfirmedTerminal.Contains(name) && !Abandoned(directory) : name is "unknown" or "tool_error";
        return new() { ["execution_id"] = id, ["state"] = name, ["in_flight_dedup"] = !blocked, ["dedup_blocked"] = blocked,
            ["orphan_guaranteed"] = orphanGuaranteed, ["record_dir"] = directory,
            ["note"] = blocked
                ? !File.Exists(Path.Combine(directory, "result.json"))
                    ? "Execution record is missing; a duplicate is NOT started. Preserve the claim and request; manual recovery of the original evidence is required."
                    : "Instance state is unconfirmed; a duplicate is NOT started. Use cancel to confirm abandonment before a new intent."
                : "Same content still running; returning the existing id." };
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
        PublicationProof proof;
        using (mutex)
        using (var index = publications.Open(() => History()))
        {
            var equivalent = EquivalentPublication(form, fingerprint, index);
            if (equivalent.Existing is not null) return equivalent.Existing;
            fingerprint = equivalent.Fingerprint;
            claimDirectory = Path.Combine(serveRoot, "_claims", fingerprint); Directory.CreateDirectory(claimDirectory);
            string claimPath = Path.Combine(claimDirectory, "claim.json");
            var preparation = index.ReadPrepared(fingerprint);
            JsonObject envelope;
            if (preparation is null)
            {
                string? existing = ClaimIdentity(fingerprint, claimPath, index);
                Require(index.Latest(fingerprint) is null || index.Latest(fingerprint) == existing,
                    "claim_index_mismatch: preserve evidence for manual recovery");
                if (existing is not null)
                {
                    Require(File.Exists(Path.Combine(serveRoot, existing, "request.json")),
                        "claim_publication_missing: " + existing + "; preserve the claim; manual recovery of the original request is required.");
                    string record = Locate(existing); string name = ExecutionRecords.Snapshot(record)["state"].String();
                    bool notStarted = StartupFailureWithoutResult(existing, record) is not null;
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
                else step = fingerprint[..12] + "-" + checked(index.Count(fingerprint) + 1).ToString(System.Globalization.CultureInfo.InvariantCulture);
                var business = new JsonObject(form.Where(p => p.Key is not "workdir" and not "previous_execution").Select(p => KeyValuePair.Create(p.Key, p.Value?.Copy())));
                business["task_ref"] = task; business["step_ref"] = step; business["attempt"] = attempt; business["cwd"] = workdir;
                foreach (var option in options) business[option.Key] = option.Value?.Copy();
                if (previousRequest is not null) business["previous_request"] = previousRequest;
                var request = RequestShape.Shape(business); requestId = request["request_id"].String(); id = ExecutionId(requestId);
                Require(!policy["require_orphan_guarantee"].IsTrue() || orphanGuaranteed, "orphan_guarantee_required_but_unavailable");
                Require(!Path.Exists(Path.Combine(BusinessPaths.Context(policy, cwd), id)),
                    "execution_identity_already_recorded: " + id + "; preserve existing evidence; manual recovery of the original publication is required.");
                envelope = new JsonObject { ["schema_version"] = 2, ["business"] = business, ["fingerprint"] = RequestDigest(request), ["content_fingerprint"] = fingerprint };
            }
            else
            {
                // Only a hash-bound prepared entry proves no launch was authorized.
                // Legacy entries and launch-committed entries never take this path.
                envelope = preparation["envelope"].Object();
                Require(Digest(preparation["policy"]) == Digest(snapshot), "publication_preparation_policy_changed");
                var request = RequestShape.Shape(envelope["business"].Object());
                requestId = request["request_id"].String(); id = index.Latest(fingerprint)!;
                Require(envelope["content_fingerprint"].Text() == fingerprint && MatchesRequest(envelope["fingerprint"].Text(), request)
                    && ExecutionId(requestId) == id, "publication_preparation_identity_conflict");
                if (File.Exists(claimPath))
                {
                    string? claimed = Read(claimPath)["execution_id"].Text();
                    Require(claimed == id || (JsonFields.IsUuid(claimed) && claimed == preparation["previous_execution_id"].Text()),
                        "claim_index_mismatch: preserve evidence for manual recovery");
                }
                Require(!policy["require_orphan_guarantee"].IsTrue() || orphanGuaranteed, "orphan_guarantee_required_but_unavailable");
                Require(!Path.Exists(Path.Combine(BusinessPaths.Context(policy, cwd), id)),
                    "execution_identity_already_recorded: " + id + "; preserve existing evidence; recovery cannot start another process.");
            }
            inputDirectory = Path.Combine(serveRoot, id);
            string requestFile = Path.Combine(inputDirectory, "request.json"), policyFile = Path.Combine(inputDirectory, "policy.json");
            proof = new(Hash(Packed(envelope)), Hash(Packed(snapshot)));
            CheckPublicationFile(requestFile, envelope); CheckPublicationFile(policyFile, snapshot);
            if (preparation is null) index.Prepare(fingerprint, id, envelope, snapshot);
            string publication = inputDirectory;
            try
            {
                Directory.CreateDirectory(inputDirectory);
                publication = requestFile; if (!File.Exists(publication)) PublishNew(publication, envelope);
                publication = policyFile; if (!File.Exists(publication)) PublishNew(publication, snapshot);
                publication = claimPath; Save(publication, new JsonObject { ["execution_id"] = id, ["published_at_unix"] = WindowsProcess.UnixNow });
            }
            catch (Exception error) when (ExecutionRecords.Handled(error))
            {
                if (!File.Exists(requestFile)) PublishNew(requestFile, envelope);
                var detail = ExecutionRecords.Error(error); detail["reason"] = publication + ": " + detail["reason"].String();
                string failureFile = Path.Combine(inputDirectory, "serve-error.json");
                if (!File.Exists(failureFile)) PublishNew(failureFile, new JsonObject { ["schema_version"] = 2, ["state"] = "not_started", ["execution_id"] = id, ["error"] = detail.Copy() });
                return StartResult(id, requestId, cwd, "start_failed", new JsonObject { ["error"] = detail }, "Input publication failed before spawning; the failure is queryable via status.");
            }
            // This flushed transition precedes releasing the locks and starting the owner.
            // A crash after this point remains unconfirmed and must never be replayed.
            index.Commit(fingerprint);
            if (StartupFailure(id) is { } recordedFailure)
                return StartResult(id, requestId, cwd, "start_failed", recordedFailure, "Recovered publication retains its recorded startup failure; no process was started.");
        }
        try { OwnerLauncher.Start(inputDirectory, cwd, spawnFlags, proof); }
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

    private static void CheckPublicationFile(string path, JsonObject expected)
    {
        if (File.Exists(path)) Require(FileHash(path) == Hash(Packed(expected)), "publication_file_conflict: " + path + "; preserve existing evidence.");
    }

    private (string Fingerprint, JsonObject? Existing) EquivalentPublication(JsonObject form, string original, PublicationIndex.Session index)
    {
        // The index lock serializes every publication, including writers using different spellings.
        // Never acquire another fingerprint lock while holding it (claim -> index is the lock order).
        string key = ContentIdentity.Key(form), claims = Path.Combine(serveRoot, "_claims");
        var fingerprints = index.Fingerprints.Concat(Directory.EnumerateDirectories(claims)
            .Where(path => File.Exists(Path.Combine(path, "claim.json"))).Select(path => Path.GetFileName(path)))
            .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        var matches = new List<(string Fingerprint, string Id, bool Prepared)>();
        foreach (string fingerprint in fingerprints)
        {
            string? id = index.Latest(fingerprint);
            var prepared = index.ReadPrepared(fingerprint);
            var snapshot = prepared ?? index.ReadPublicationSnapshot(fingerprint);
            string claim = Path.Combine(claims, fingerprint, "claim.json");
            if (id is null && File.Exists(claim))
            {
                // The existing exact-key recovery path owns malformed-claim diagnostics.
                if (fingerprint == original) continue;
                id = Read(claim)["execution_id"].Text();
                Require(JsonFields.IsUuid(id), "publication_identity_unverifiable: preserve the original claim");
            }
            if (id is null) continue;
            string path = Path.Combine(serveRoot, id, "request.json");
            JsonObject envelope;
            if (snapshot is not null) envelope = snapshot["envelope"].Object();
            else if (File.Exists(path)) envelope = ReadRequest(path);
            else
            {
                Require(fingerprint == original, "publication_identity_unverifiable: " + id + "; recover the original request before starting new work");
                return (original, null);
            }
            if (fingerprint != original && ContentIdentity.FromEnvelope(envelope) != key) continue;
            matches.Add((fingerprint, id, prepared is not null));
            if (prepared is not null) continue;
            Directory.CreateDirectory(Path.GetDirectoryName(claim)!);
            Require(ClaimIdentity(fingerprint, claim, index) == id, "claim_index_mismatch: preserve evidence for manual recovery");
            string directory = Locate(id), state = ExecutionRecords.Snapshot(directory)["state"].String();
            if (StartupFailureWithoutResult(id, directory) is null && !ExecutionRecords.ConfirmedTerminal.Contains(state) && !Abandoned(directory))
                return (fingerprint, Existing(id));
        }
        var pending = matches.Where(match => match.Prepared).ToArray();
        Require(pending.Length <= 1, "equivalent_publications_unconfirmed: preserve all original reservations");
        if (pending.Length == 1) return (pending[0].Fingerprint, null);
        string? previous = form["previous_execution"].Text();
        if (JsonFields.IsUuid(previous) && File.Exists(Path.Combine(serveRoot, previous!, "request.json")))
        {
            string? fingerprint = ReadRequest(Path.Combine(serveRoot, previous!, "request.json"))["content_fingerprint"].Text();
            if (matches.Any(match => match.Fingerprint == fingerprint)) return (fingerprint!, null);
        }
        return (matches.Any(match => match.Fingerprint == original) || matches.Count == 0 ? original : matches[0].Fingerprint, null);
    }

    private JsonObject StartResult(string id, string requestId, string cwd, string state, JsonObject? failure, string note)
    {
        var result = new JsonObject { ["execution_id"] = id, ["request_id"] = requestId, ["state"] = state, ["in_flight_dedup"] = false,
            ["orphan_guaranteed"] = orphanGuaranteed, ["record_dir"] = Path.Combine(BusinessPaths.Context(policy, cwd), id), ["note"] = note };
        if (state != "starting") result["serve_error"] = failure;
        return result;
    }
}
