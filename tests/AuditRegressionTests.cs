using System.Collections.Specialized;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json.Nodes;
using CommandEntry;
using Microsoft.Win32.SafeHandles;
using static CommandEntry.RecordJson;

namespace CommandEntry.Tests;

internal static partial class AuditRegressionTests
{
    [LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial SafeFileHandle CreateFileW(string path, uint access, uint sharing, nint security, uint disposition, uint flags, nint template);

    // Run every independent reported trigger even when an earlier one fails.
    [Case]
    private static void ConfirmedAuditRegressions()
    {
        Action[] checks = [EnvironmentCollisionsHaveStableValues, UrlCredentialsAreRedacted,
            SnapshotReadsAllowReplacementButBindingsStayLocked, ConcurrentSnapshotsRemainComplete,
            FailedSaveRemovesOnlyItsScratchFile, MissingRecordsHaveHonestWaitAndCancelResults,
            InvalidFailureSidecarsCannotAuthorizeAnotherExecution, MissingPublicationPreservesClaim,
            HistoricalExecutionIdentityCannotBeReissued, MetricsReportUnparsedRecords, QueriesRejectIgnoredCwd,
            UnicodeUrlCredentialsAreRedacted, UnicodeBearerCredentialsAreRedacted, UnicodeTokensAreRedacted,
            SaveReplacesSnapshotWhileReaderRemainsOpen, EmptyRecordStartupFailureIsConsistent,
            PublishedTerminalSurvivesOwnerExitObservation];
        var failures = new List<Exception>();
        foreach (var check in checks)
        {
            try { check(); Console.WriteLine("AUDIT PASS " + check.Method.Name); }
            catch (Exception error)
            {
                Console.WriteLine("AUDIT FAIL " + check.Method.Name + ": " + error.Message);
                failures.Add(new Exception(check.Method.Name, error));
            }
        }
        if (failures.Count != 0) throw new AggregateException(failures);
    }

    private static void EnvironmentCollisionsHaveStableValues()
    {
        (string Key, string Value)[] entries = [("http_proxy", "lower"), ("HTTP_PROXY", "upper"),
            ("PaTh", "mixed"), ("PATH", "canonical"), ("EMPTY", ""), ("UNICODE", "中文😀"),
            (OwnerLauncher.InputVariable.ToLowerInvariant(), "untrusted-fixture")];
        string? expected = null;
        foreach (var ordered in new[] { entries, entries.Reverse().ToArray() })
        {
            var source = new OrderedDictionary(StringComparer.Ordinal);
            foreach (var (key, value) in ordered) source.Add(key, value);
            string block = new(OwnerLauncher.EnvironmentBlock(source, "F:\\reviewed-input"));
            Check.True(block.EndsWith("\0\0", StringComparison.Ordinal));
            if (expected is not null) Check.Equal(expected, block);
            expected = block;
            var pairs = block.Split('\0', StringSplitOptions.RemoveEmptyEntries).Select(entry => entry.Split('=', 2)).ToArray();
            var values = pairs.ToDictionary(pair => pair[0], pair => pair[1], StringComparer.OrdinalIgnoreCase);
            Check.Equal(5, values.Count); Check.Equal("upper", values["http_proxy"]); Check.Equal("canonical", values["Path"]);
            Check.Equal("", values["EMPTY"]); Check.Equal("中文😀", values["UNICODE"]);
            Check.Equal("F:\\reviewed-input", values[OwnerLauncher.InputVariable]);
            Check.True(pairs.Select(pair => pair[0]).SequenceEqual(pairs.Select(pair => pair[0]).Order(StringComparer.OrdinalIgnoreCase)));
        }
    }

    private static void UnicodeUrlCredentialsAreRedacted()
    {
        CheckUnicodeRedaction("https://user:synthetic-v6-value@host.example/x", "https://[REDACTED userinfo]@host.example/x");
        using var f = new Fixture();
        const string source = "代理https://user:fixture@host.example/x\n代理Bearer synthetic-v6-value\n代理sk-syntheticabcdefghijkl";
        const string expected = "代理https://[REDACTED userinfo]@host.example/x\n代理[REDACTED bearer]\n代理[REDACTED]\n";
        var state = f.Execute(f.Form("text", source)); Check.Equal("exited", state["state"].String());
        foreach (string stream in new[] { "stdout", "stderr" })
            Check.Equal(expected, f.Output(state["execution_id"].String(), stream));
    }

    private static void UnicodeBearerCredentialsAreRedacted() => CheckUnicodeRedaction(
        "Bearer synthetic-v6-value", "[REDACTED bearer]");

    private static void UnicodeTokensAreRedacted()
    {
        foreach (string token in new[] { "sk-syntheticabcdefghijkl", "ghp_syntheticabcdefghijkl", "eyJsynthetic.abc.def" })
            CheckUnicodeRedaction(token, "[REDACTED]");
    }

    private static void CheckUnicodeRedaction(string input, string expected)
    {
        foreach (string prefix in new[] { "", "代理", "é", "😀", "\u0301", "K", "ſ" })
        {
            string source = prefix + input, redacted = prefix + expected;
            Check.Equal(redacted, OutputCapture.RedactLine(source));
            Check.Equal(redacted, ExecutionRecords.Error(new ArgumentException(source))["reason"].String());
            using var f = new Fixture(); string file = f.FilePath("unicode-output.txt");
            using (var capture = new OutputCapture(file))
            {
                capture.Feed(Utf8.GetBytes(source + "\n"), final: true);
                var metadata = capture.Metadata();
                Check.Equal(redacted + "\n", metadata["preview_head"].String());
                Check.Equal(redacted + "\n", metadata["preview_tail"].String());
            }
            Check.Equal(redacted + "\n", File.ReadAllText(file, Utf8));
        }
        // Preserve ASCII identifier boundaries, including underscore.
        Check.Equal("_" + input, OutputCapture.RedactLine("_" + input));
        if (!input.StartsWith("https://", StringComparison.Ordinal))
            Check.Equal("prefix" + input, OutputCapture.RedactLine("prefix" + input));
        Check.Equal("//user:fixture@host.example/x", OutputCapture.RedactLine("//user:fixture@host.example/x"));
    }

    private static void SaveReplacesSnapshotWhileReaderRemainsOpen()
    {
        using var f = new Fixture(); string file = f.Write("快照 😀.json", "{\"n\":1}");
        using (var held = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete))
        {
            Save(file, new JsonObject { ["n"] = 2 });
            Check.Equal(2L, Read(file)["n"].Integer("n"));
            using var reader = new StreamReader(held, Utf8);
            Check.Equal("{\"n\":1}", reader.ReadToEnd());
        }
        Check.Equal(0, Directory.GetFiles(f.DirectoryPath, "*.tmp").Length);
        using (var bindings = new FileBindings())
        {
            bindings.Add(file);
            Check.Throws<IOException>(() => Save(file, new JsonObject { ["n"] = 3 }));
            Check.Equal(2L, Read(file)["n"].Integer("n"));
        }
        using (var mutex = new FileMutex(file))
            Check.Throws<IOException>(() => Save(file, new JsonObject { ["n"] = 3 }));
        Check.Equal(2L, Read(file)["n"].Integer("n"));

        // Exercise the selected server binary too, including Native AOT runs.
        var started = f.Start(f.Form("sleep", "1500")); string id = started["execution_id"].String();
        string result = Path.Combine(f.DirectoryPath, ".codex-command-records", id, "result.json");
        using var heldResult = new FileStream(result, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
        using var snapshotReader = new StreamReader(heldResult, Utf8);
        string before = snapshotReader.ReadToEnd();
        Check.True(!ExecutionRecords.Terminal.Contains(JsonNode.Parse(before)!["state"].String()));
        Check.Equal("exited", f.Terminal(id)["state"].String());
        Check.Equal("exited", Read(result)["state"].String());
        heldResult.Position = 0; snapshotReader.DiscardBufferedData();
        Check.Equal(before, snapshotReader.ReadToEnd());

        // The previous File.Move path did not impose a MAX_PATH limit.
        string longRoot = f.FilePath(new string('a', 100));
        Check.True(longRoot.Length < 260);
        f.Policy["serve_root"] = longRoot; f.Restart();
        var form = f.Form("location"); string historicalId = Guid.NewGuid().ToString();
        string claim = Path.Combine(longRoot, "_claims", Digest(form), "claim.json");
        Check.True(claim.Length > 260);
        string publication = Path.Combine(longRoot, historicalId); Directory.CreateDirectory(publication);
        WriteNew(Path.Combine(publication, "request.json"), new JsonObject { ["content_fingerprint"] = Digest(form),
            ["business"] = new JsonObject { ["cwd"] = f.DirectoryPath } });
        // Claim recovery exercises Save at a long path without invoking a business process.
        var longPathResult = f.Start(form);
        Check.Equal(historicalId, longPathResult["execution_id"].String()); Check.True(longPathResult["dedup_blocked"].IsTrue());
        Check.Equal(historicalId, Read(claim)["execution_id"].String());
    }

    private static void EmptyRecordStartupFailureIsConsistent()
    {
        foreach (bool createDirectory in new[] { false, true })
        {
            using var f = new Fixture(); var form = f.Form("location"); string id = SeedPublication(f, form);
            string record = Path.Combine(f.DirectoryPath, ".codex-command-records", id);
            if (createDirectory) Directory.CreateDirectory(record);
            WriteNew(Path.Combine(f.Serve, id, "serve-error.json"), new JsonObject { ["state"] = "not_started", ["execution_id"] = null,
                ["error"] = new JsonObject { ["kind"] = "OSError", ["reason"] = "synthetic failure before first Save" } });
            var query = new JsonObject { ["execution_id"] = id };
            Check.Equal("start_failed", f.Client.Call("status", query)["state"].String());
            var wait = f.Client.Call("wait", query);
            Check.Equal("start_failed", wait["state"].String()); Check.Equal("terminal", wait["wait_outcome"].String());
            Check.Equal("already_terminal", f.Client.Call("cancel", query)["cancel_action"].String());
            Check.True(!File.Exists(Path.Combine(record, "cancel-request.json")));
            Check.True(!File.Exists(Path.Combine(record, "cancel-outcome.json")));
            var next = f.Start(form); Check.True(next["execution_id"].String() != id);
            Check.Equal("exited", f.Terminal(next["execution_id"].String())["state"].String());
            Check.True(File.Exists(Path.Combine(f.Serve, id, "serve-error.json")));
        }
    }

    private static void PublishedTerminalSurvivesOwnerExitObservation()
    {
        using var f = new Fixture(); string file = f.FilePath("result.json");
        foreach (string final in new[] { "rejected", "exited", "cancelled", "timed_out", "running" })
        {
            Save(file, new JsonObject { ["state"] = "starting", ["owner"] = new JsonObject { ["pid"] = 42, ["creation_time"] = 123UL } });
            int observations = 0;
            var snapshot = ExecutionRecords.Snapshot(f.DirectoryPath, pid =>
            {
                Check.Equal(42, pid); observations++;
                Save(file, new JsonObject { ["state"] = final, ["process"] = new JsonObject { ["exit_code"] = 125 } });
                return new JsonObject { ["alive"] = false, ["creation_time"] = null };
            });
            Check.Equal(1, observations);
            Check.Equal(final == "running" ? "unknown" : final, snapshot["state"].String());
            if (final != "running") Check.Equal(125L, snapshot["process"]!["exit_code"].Integer("exit_code"));
            else Check.Equal("owner_instance_not_confirmed", snapshot["reason"].String());
            Check.Equal(final, Read(file)["state"].String());
        }
    }

    private static void UrlCredentialsAreRedacted()
    {
        const string fixtureSecret = "synthetic-audit-value";
        foreach (string url in new[] { "https://user:" + fixtureSecret + "@host.example:8443/x",
            "HTTP://user:" + fixtureSecret + "%40suffix@[::1]/", "socks5://user:" + fixtureSecret + "@host.example" })
        {
            string message = "Duplicate entry [proxy, " + url + "]";
            Check.True(!OutputCapture.RedactLine(message).Contains(fixtureSecret));
            Check.True(!ExecutionRecords.Error(new ArgumentException(message)).ToJsonString().Contains(fixtureSecret));
            Check.Contains("[REDACTED userinfo]@", OutputCapture.RedactLine(message));
        }
        const string ordinary = "File missing: https://host.example/a; contact user@example.com";
        Check.Equal(ordinary, OutputCapture.RedactLine(ordinary));
        using var f = new Fixture(); string value = "https://user:" + fixtureSecret + "@host.example/x";
        var state = f.Execute(f.Form("echo", value)); Check.Equal("exited", state["state"].String());
        string output = f.Output(state["execution_id"].String());
        Check.True(!output.Contains(fixtureSecret)); Check.Contains("[REDACTED userinfo]@host.example/x", output);
    }

    private static void SnapshotReadsAllowReplacementButBindingsStayLocked()
    {
        using var f = new Fixture(); string file = f.Write("snapshot.json", "{\"n\":1}");
        // DELETE access models the handle required to replace the destination.
        // Merely opening/closing this handle does not delete the test file.
        using (var replacement = CreateFileW(file, 0x00010000, 7, 0, 3, 0x80, 0))
        {
            if (replacement.IsInvalid) throw new Win32Exception(Marshal.GetLastPInvokeError());
            Check.Equal(1L, Read(file)["n"].Integer("n"));
        }
        using (var bindings = new FileBindings())
        {
            bindings.Add(file);
            using var blocked = CreateFileW(file, 0x00010000, 7, 0, 3, 0x80, 0);
            Check.True(blocked.IsInvalid); Check.Equal(32, Marshal.GetLastPInvokeError());
            Check.Throws<IOException>(() => File.WriteAllText(file, "{}", Utf8));
        }
        Save(file, new JsonObject { ["n"] = 2 }); Check.Equal(2L, Read(file)["n"].Integer("n"));
        string bom = f.FilePath("bom.json"); File.WriteAllBytes(bom, [0xef, 0xbb, 0xbf, .. Utf8.GetBytes("{\"n\":3}")]);
        Check.Equal(3L, Read(bom)["n"].Integer("n"));
        string invalid = f.FilePath("invalid-utf8.json"); File.WriteAllBytes(invalid, [0xff]);
        Check.Throws<DecoderFallbackException>(() => Read(invalid));
    }

    private static void ConcurrentSnapshotsRemainComplete()
    {
        using var f = new Fixture(); string file = f.FilePath("changing.json");
        Save(file, new JsonObject { ["version"] = 0, ["payload"] = new string('a', 4096) });
        using var start = new ManualResetEventSlim();
        var writer = Task.Run(() =>
        {
            start.Wait();
            for (int i = 1; i <= 100; i++) Save(file, new JsonObject { ["version"] = i, ["payload"] = new string(i % 2 == 0 ? 'a' : 'b', 4096) });
        });
        var reader = Task.Run(() =>
        {
            start.Wait();
            for (int i = 0; i < 500; i++)
            {
                var value = Read(file); long version = value["version"].Integer("version");
                Check.Equal(new string(version % 2 == 0 ? 'a' : 'b', 4096), value["payload"].String());
            }
        });
        start.Set(); Task.WhenAll(writer, reader).GetAwaiter().GetResult();
        Check.Equal(100L, Read(file)["version"].Integer("version"));
    }

    private static void FailedSaveRemovesOnlyItsScratchFile()
    {
        using var f = new Fixture(); string file = f.Write("locked.json", "{\"n\":1}");
        string unrelated = f.Write("keep.tmp", "retained evidence");
        Exception? failure = null;
        using (var reader = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            try { Save(file, new JsonObject { ["n"] = 2 }); }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException) { failure = error; }
        }
        Check.True(failure is not null); Check.Equal("{\"n\":1}", File.ReadAllText(file));
        Check.Equal(0, Directory.GetFiles(f.DirectoryPath, "locked.json.*.tmp").Length);
        Check.Equal("retained evidence", File.ReadAllText(unrelated));
    }

    private static string SeedPublication(Fixture f, JsonObject form)
    {
        string id = Guid.NewGuid().ToString(), directory = Path.Combine(f.Serve, id); Directory.CreateDirectory(directory);
        WriteNew(Path.Combine(directory, "request.json"), new JsonObject { ["content_fingerprint"] = Digest(form),
            ["business"] = new JsonObject { ["cwd"] = f.DirectoryPath } });
        return id;
    }

    private static void MissingRecordsHaveHonestWaitAndCancelResults()
    {
        using var f = new Fixture(); var form = f.Form("location"); string id = SeedPublication(f, form);
        var query = new JsonObject { ["execution_id"] = id };
        var wait = f.Client.Call("wait", query); Check.Equal("unknown", wait["state"].String()); Check.Equal("unconfirmed", wait["wait_outcome"].String());
        var blocked = f.Start(form); Check.True(blocked["dedup_blocked"].IsTrue());
        Check.Contains("manual recovery", blocked["note"].String()); Check.True(!blocked["note"].String().Contains("Use cancel"));
        var cancel = f.Client.Raw("cancel", query); Check.True(cancel["isError"].IsTrue()); Check.Contains("manual recovery", cancel.ToJsonString());
        Check.True(!Directory.Exists(Path.Combine(f.DirectoryPath, ".codex-command-records", id)));
        WriteNew(Path.Combine(f.Serve, id, "serve-error.json"), new JsonObject { ["state"] = "not_started", ["execution_id"] = id,
            ["error"] = new JsonObject { ["kind"] = "OSError", ["reason"] = "synthetic failure" } });
        var failed = f.Client.Call("wait", query); Check.Equal("start_failed", failed["state"].String()); Check.Equal("terminal", failed["wait_outcome"].String());
        Check.Equal("already_terminal", f.Client.Call("cancel", query)["cancel_action"].String());
    }

    private static void InvalidFailureSidecarsCannotAuthorizeAnotherExecution()
    {
        foreach (bool createDirectory in new[] { false, true })
        foreach (string bad in new[] { "{", "{}", "{\"state\":\"running\"}",
            "{\"state\":\"not_started\",\"execution_id\":\"00000000-0000-4000-8000-000000000000\",\"error\":{\"kind\":\"OSError\",\"reason\":\"fixture\"}}" })
        {
            using var f = new Fixture(); var form = f.Form("location"); string id = SeedPublication(f, form);
            if (createDirectory) Directory.CreateDirectory(Path.Combine(f.DirectoryPath, ".codex-command-records", id));
            string sidecar = Path.Combine(f.Serve, id, "serve-error.json"); File.WriteAllText(sidecar, bad, Utf8);
            var start = f.Start(form);
            if (start["state"].Text() == "starting") _ = f.Terminal(start["execution_id"].String());
            Check.Equal(id, start["execution_id"].String()); Check.True(start["dedup_blocked"].IsTrue());
            Check.Contains("manual recovery", start["note"].String());
            var wait = f.Client.Call("wait", new JsonObject { ["execution_id"] = id });
            Check.Equal("unknown", wait["state"].String()); Check.Equal("unconfirmed", wait["wait_outcome"].String());
            var cancel = f.Client.Raw("cancel", new JsonObject { ["execution_id"] = id }); Check.True(cancel["isError"].IsTrue());
            Check.Contains("record_missing_unconfirmed", cancel.ToJsonString()); Check.Equal(bad, File.ReadAllText(sidecar));
        }
    }

    private static void MissingPublicationPreservesClaim()
    {
        using var f = new Fixture(); var form = f.Form("location"); string id = Guid.NewGuid().ToString();
        string directory = Path.Combine(f.Serve, "_claims", Digest(form)); Directory.CreateDirectory(directory);
        string claim = Path.Combine(directory, "claim.json"); WriteNew(claim, new JsonObject { ["execution_id"] = id });
        string hash = FileHash(claim);
        var result = f.Client.Raw("start_operation", form); Check.True(result["isError"].IsTrue());
        Check.Contains("claim_publication_missing", result.ToJsonString()); Check.Contains(id, result.ToJsonString());
        Check.Equal(hash, FileHash(claim)); Check.Equal(0, Directory.GetFiles(f.Serve, "request.json", SearchOption.AllDirectories).Length);
    }

    private static void HistoricalExecutionIdentityCannotBeReissued()
    {
        using var f = new Fixture(); var form = f.Form("output", "1");
        string id = ExecutionId(RequestId("mcp-direct", Digest(form)[..12] + "-1", 0));
        string directory = Path.Combine(f.DirectoryPath, ".codex-command-records", id); Directory.CreateDirectory(directory);
        string record = Path.Combine(directory, "result.json"); WriteNew(record, new JsonObject { ["state"] = "exited", ["execution_id"] = id });
        string hash = FileHash(record);
        var result = f.Client.Raw("start_operation", form); Check.True(result["isError"].IsTrue());
        Check.Contains("execution_identity_already_recorded", result.ToJsonString()); Check.Contains(id, result.ToJsonString());
        Check.Equal(hash, FileHash(record)); Check.True(!Directory.Exists(Path.Combine(f.Serve, id)));
        Check.True(!File.Exists(f.FilePath("writes.txt")));
    }

    private static void MetricsReportUnparsedRecords()
    {
        using var f = new Fixture(); string records = f.FilePath("hooks"); Directory.CreateDirectory(records);
        WriteNew(Path.Combine(records, "valid.json"), new JsonObject { ["route"] = "shell_denied" });
        File.WriteAllText(Path.Combine(records, "bad.json"), "{broken", Utf8);
        string events = f.Write("events.jsonl", "{\"kind\":\"startup\"}\n{broken\nnull\n");
        var result = Fixture.Run(TestRunner.Server, ["metrics", "--records", records, "--events", events, "--serve", f.Serve]);
        Check.Equal(0, result.Exit); var metrics = JsonNode.Parse(result.Out).Object();
        Check.True(!metrics["complete"].IsTrue()); Check.Equal(1L, metrics["hook"]!["unparsed_records"].Integer("count"));
        Check.Equal(2L, metrics["server"]!["unparsed_event_lines"].Integer("count"));
        Check.Equal(1L, metrics["hook"]!["total_decisions"].Integer("count")); Check.Equal(1L, metrics["server"]!["startup_events"].Integer("count"));
        Check.Equal("{broken", File.ReadAllText(Path.Combine(records, "bad.json")));
    }

    private static void QueriesRejectIgnoredCwd()
    {
        using var f = new Fixture(); string id = SeedPublication(f, f.Form("location"));
        foreach (string tool in new[] { "status", "wait", "cancel", "output" })
        {
            var result = f.Client.Raw(tool, new JsonObject { ["execution_id"] = id, ["cwd"] = f.DirectoryPath });
            Check.True(result["isError"].IsTrue()); Check.Contains("unknown_form_fields", result.ToJsonString());
        }
    }
}
