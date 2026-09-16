using System.Diagnostics;
using System.Text;
using System.Text.Json.Nodes;
using CommandEntry;
using static CommandEntry.RecordJson;

namespace CommandEntry.Tests;

internal static class AuditFollowupTests
{
    [Case]
    internal static void ObserveSeparatesExit259FromRunning()
    {
        foreach (int code in new[] { 259, 0, 7 })
        {
            using var process = Process.Start(WindowsProcess.StartInfo(TestRunner.ProbeExe,
                ["probe", "gated-exit", code.ToString()], TestRunner.Root))!;
            _ = process.SafeHandle; // Keep the exited kernel process object observable.
            try
            {
                var live = WindowsProcess.Observe(process.Id);
                Check.True(live["alive"].IsTrue());
                Check.True(live["exit_code"] is null);
                ulong creation = live["creation_time"]!.GetValue<ulong>();
                Check.Equal("instance_mismatch", WindowsProcess.TerminateSameInstance(process.Id, creation + 1)["reason"].Text());
                process.StandardInput.WriteLine(); process.StandardInput.Flush();
                Check.True(process.WaitForExit(10000));
                Check.Equal(code, process.ExitCode);
                var dead = WindowsProcess.Observe(process.Id);
                Check.Equal(false, dead["alive"]!.GetValue<bool>());
                Check.Equal((uint)code, dead["exit_code"]!.GetValue<uint>());
                Check.Equal(creation, dead["creation_time"]!.GetValue<ulong>());
            }
            finally { if (!process.HasExited) { process.Kill(); process.WaitForExit(); } }
        }
    }

    [Case]
    internal static void Exit259CompletesThroughMcp()
    {
        using var f = new Fixture();
        var result = f.Execute(f.Form("exit", "259"));
        Check.Equal("exited", result["state"].Text());
        Check.Equal(259, result["process"]!["exit_code"]!.GetValue<int>());
    }

    [Case]
    internal static void OutputQuotaKeepsLatestPreviewWithBoundedAllocations()
    {
        using var f = new Fixture();
        using var capture = new OutputCapture(f.FilePath("quota.txt"), quota: 1024);
        byte[] chunk = Utf8.GetBytes(new string('x', 1023) + "\n");
        for (int i = 0; i < 32; i++) capture.Feed(chunk);
        long before = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < 4096; i++) capture.Feed(chunk);
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Console.WriteLine($"OUTPUT_ALLOCATION input={4096L * chunk.Length} allocated={allocated}");
        string latest = string.Concat(Enumerable.Repeat("😀", 511)) + "\n";
        byte[] ending = Utf8.GetBytes(latest);
        foreach (byte value in ending) capture.Feed(new[] { value });
        capture.Feed([], final: true);
        var metadata = capture.Metadata();
        Check.Equal(new string('x', 512), metadata["preview_head"].Text());
        Check.Equal(latest, metadata["preview_tail"].Text());
        Check.Equal(1024L, metadata["retained_utf8_bytes"]!.GetValue<long>());
        Check.Equal(4128L * chunk.Length + ending.Length, metadata["captured_bytes"]!.GetValue<long>());
        Check.Equal(4128L, metadata["missing_lines"]!.GetValue<long>());
        Check.True(metadata["capture_complete"].IsTrue());
        Check.True(!metadata["decoding_loss"].IsTrue());
        Check.Equal(new string('x', 1023) + "\n", File.ReadAllText(f.FilePath("quota.txt"), Utf8));
        Check.True(allocated < 4096L * chunk.Length * 8, "Output allocation exceeds 8 bytes per input byte: " + allocated);
    }

    [Case]
    internal static void LargeFeedPreservesCrLfAcrossInternalDecodeChunks()
    {
        using var capture = new OutputCapture(null);
        capture.Feed(Utf8.GetBytes(new string('x', 8191) + "\r\ny\n"), final: true);
        var metadata = capture.Metadata();
        Check.Equal(2L, metadata["missing_lines"]!.GetValue<long>());
        Check.Equal(new string('x', 508) + "\r\ny\n", metadata["preview_tail"].Text());
        Check.Json(new JsonArray(new JsonArray(1, 2)), metadata["missing_decoded_line_ranges"]);
    }

    [Case]
    internal static void HotPublicationDoesNotReadUnrelatedHistory()
    {
        using var f = new Fixture();
        var first = f.Execute(f.Form("text", "first"));
        string path = Path.Combine(f.Serve, first["execution_id"].String(), "request.json");
        using var held = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None);
        Check.Equal("exited", f.Execute(f.Form("text", "second"))["state"].Text());
        string events = File.ReadAllText(f.FilePath("logs/server-events.jsonl"), Utf8);
        Check.True(!events.Contains("request_record_unreadable"), "Hot publication reread unrelated history: " + events);
    }

    [Case]
    internal static void SentinelRejectsMalformedPreToolIdentity()
    {
        foreach (string field in new[] { "", ",\"tool_name\":null", ",\"tool_name\":12", ",\"tool_name\":false",
            ",\"tool_name\":[]", ",\"tool_name\":{}", ",\"tool_name\":\"\"", ",\"tool_name\":\"  \"" })
        {
            var result = Sentinel.Handle("{\"hook_event_name\":\"PreToolUse\"" + field + "}");
            Check.Equal("deny", result.Answer["hookSpecificOutput"]?["permissionDecision"].Text());
            Check.Equal("invalid_event_denied", result.Metadata["route"].Text());
        }
        foreach (string name in new[] { "Bash", "shell", "exec_command", "Read", "Write", "Edit", "FutureTool" })
        {
            var result = Sentinel.Handle(new JsonObject { ["hook_event_name"] = "PreToolUse", ["tool_name"] = name,
                ["tool_input"] = "synthetic-private-input" }.ToJsonString());
            Check.Equal(Sentinel.ShellTools.Contains(name) ? "deny" : "passthrough", result.Metadata["decision"].Text());
            Check.True(!result.Metadata.ToJsonString().Contains("synthetic-private-input"));
        }
        Check.Equal(0, Sentinel.Handle("{\"hook_event_name\":\"PostToolUse\"}").Answer.Count);
    }

    [Case]
    internal static void PublicationIndexCountsLegacyRetriesAndSynchronizesServers()
    {
        using var f = new Fixture();
        string fingerprint = new('a', 64);
        string first = Guid.NewGuid().ToString(), retry = Guid.NewGuid().ToString();
        string firstPath = Path.Combine(f.Serve, first, "request.json"), retryPath = Path.Combine(f.Serve, retry, "request.json");
        Directory.CreateDirectory(Path.GetDirectoryName(firstPath)!);
        Directory.CreateDirectory(Path.GetDirectoryName(retryPath)!);
        WriteNew(firstPath, new JsonObject { ["content_fingerprint"] = fingerprint });
        WriteNew(retryPath, new JsonObject { ["content_fingerprint"] = fingerprint });
        File.SetLastWriteTimeUtc(firstPath, DateTime.UtcNow.AddMinutes(-1));
        int scans = 0;
        IEnumerable<(string Path, JsonObject Envelope)> History()
        {
            scans++;
            return new[] { (firstPath, Read(firstPath)), (retryPath, Read(retryPath)) };
        }
        var one = new PublicationIndex(f.Serve); var two = new PublicationIndex(f.Serve);
        using (var index = one.Open(History)) { Check.Equal(2L, index.Count(fingerprint)); Check.Equal(retry, index.Latest(fingerprint)); }
        using (var index = two.Open(History)) Check.Equal(2L, index.Count(fingerprint));
        string reserved = Guid.NewGuid().ToString();
        using (var index = one.Open(History)) index.Reserve(fingerprint, reserved);
        using (var held = new FileStream(firstPath, FileMode.Open, FileAccess.Read, FileShare.None))
        using (var index = two.Open(History)) { Check.Equal(3L, index.Count(fingerprint)); Check.Equal(reserved, index.Latest(fingerprint)); }
        Check.Equal(2, scans);
        using (var index = new PublicationIndex(f.Serve).Open(History))
        { Check.Equal(3L, index.Count(fingerprint)); Check.Equal(reserved, index.Latest(fingerprint)); }
        string journal = Path.Combine(f.Serve, "publication-index.jsonl");
        File.AppendAllText(journal, "{", Utf8);
        string before = FileHash(journal);
        Check.Throws<InvalidRequest>(() => { using var index = two.Open(History); }, "publication_index_incomplete");
        Check.Throws<InvalidRequest>(() => { using var index = new PublicationIndex(f.Serve).Open(History); }, "publication_index_incomplete");
        Check.Equal(before, FileHash(journal));
    }

    [Case]
    internal static void UnpublishedReservationBlocksBothWarmAndRestartedServers()
    {
        using var f = new Fixture();
        var form = f.Form("text", "reservation");
        string id = f.Execute(form)["execution_id"].String();
        string fingerprint = f.Envelope(id)["content_fingerprint"].String();
        string journal = Path.Combine(f.Serve, "publication-index.jsonl");
        var reservation = new JsonObject { ["schema_version"] = 1, ["content_fingerprint"] = fingerprint,
            ["execution_id"] = Guid.NewGuid().ToString(), ["count"] = 2 };
        File.AppendAllText(journal, Utf8.GetString(Packed(reservation)) + "\n", Utf8);
        string before = FileHash(journal);
        for (int i = 0; i < 2; i++)
        {
            var response = f.Client.Raw("start_operation", form);
            Check.True(response["isError"].IsTrue());
            Check.Contains("claim_index_mismatch", response.ToJsonString());
            Check.Equal(1, Directory.EnumerateFiles(f.Serve, "request.json", SearchOption.AllDirectories).Count());
            Check.Equal(before, FileHash(journal));
            if (i == 0) f.Restart();
        }
    }

    [Case]
    internal static void QuotaSkipsLargeLineButRetainsLaterSmallRedactedLines()
    {
        using var f = new Fixture();
        using var capture = new OutputCapture(f.FilePath("small.txt"), quota: 200);
        string large = new string('x', 300) + "\n";
        capture.Feed(Utf8.GetBytes(large + "ok\n-----BEGIN PRIVATE KEY-----\nsynthetic-key\n-----END PRIVATE KEY-----\npassword=synthetic\n"), final: true);
        string retained = "ok\n" + string.Concat(Enumerable.Repeat("[REDACTED private key material]\n", 3)) + "[REDACTED credential line]\n";
        Check.Equal(retained, File.ReadAllText(f.FilePath("small.txt"), Utf8));
        var meta = capture.Metadata();
        Check.Equal(large + retained, meta["preview_tail"].Text());
        Check.Equal(1L, meta["missing_lines"]!.GetValue<long>());
        Check.True(meta["redacted"].IsTrue());
    }
}
