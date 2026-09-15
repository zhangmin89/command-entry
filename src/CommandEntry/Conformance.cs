#if CONFORMANCE
// Cross-language conformance harness (Python vs C#), compiled only with
// -p:DefineConstants=CONFORMANCE. Not part of the shipped binary.
using System.Diagnostics;
using System.Globalization;
using System.Text.Json.Nodes;

namespace CommandEntry;

internal static class Conformance
{
    private static string Root => Environment.CurrentDirectory;
    private static string PythonExe => RecordJson.Read(Path.Combine(Root, "policy.json"))["python"].String();
    private static int failures;

    internal static int Run()
    {
        // 1. Canonical JSON text must equal Python json.dumps(ensure_ascii=True, sort_keys=True, separators).
        Check("packed.basic", Text(JsonNode.Parse("{\"b\":1,\"a\":[true,null,\"x\\u00e9\\ud83d\\ude00\"],\"0\":{}}")!),
            "{\"0\":{},\"a\":[true,null,\"x\\u00e9\\ud83d\\ude00\"],\"b\":1}");
        Check("packed.bigint", Text(JsonNode.Parse("123456789012345678901234567890")!), "123456789012345678901234567890");
        Check("packed.negzero", Text(JsonValue.Create(-0.0)!), Python("print(repr(float('-0.0')))"));
        foreach (string raw in new[] { "1e16", "1.5e16", "123456789012345678.0", "1e17", "1e-5", "1e-4",
            "0.1", "1e15", "3.141592653589793", "1e300", "5e-324", "1e22", "123456789012345678901234567890.0" })
            Check($"number.{raw}", Text(JsonNode.Parse(raw)!), Python($"import json;print(json.dumps(json.loads('{raw}')))"));

        // 2. Python sorts Unicode code points: U+E000 precedes U+1F600.
        Check("packed.keyorder", Text(new JsonObject { ["\ud83d\ude00"] = 1, ["\ue000"] = 2 }),
            Python("import json;print(json.dumps({'\ud83d\ude00':1,'\ue000':2},ensure_ascii=True,sort_keys=True,separators=(',',':')))"));

        // 3. Identity derivation must equal Python uuid5 over the same packed payloads.
        Check("request_id", RecordJson.RequestId("mcp-direct", "step-1", 0),
            Python("import uuid,json;print(uuid.uuid5(uuid.UUID('a93e3e64-c90b-4ca6-a8da-bcf070c04196'),json.dumps(['mcp-direct','step-1',0],ensure_ascii=True,sort_keys=True,separators=(',',':'))))"));
        Check("logical_id", RecordJson.LogicalId("mcp-direct", "step-1"),
            Python("import uuid,json;print(uuid.uuid5(uuid.UUID('a93e3e64-c90b-4ca6-a8da-bcf070c04196'),json.dumps(['mcp-direct','step-1'],ensure_ascii=True,sort_keys=True,separators=(',',':'))))"));
        Check("execution_id", RecordJson.ExecutionId("40f8c464-d385-5210-aced-65a01e9db412"),
            Python("import uuid;print(uuid.uuid5(uuid.UUID('40f8c464-d385-5210-aced-65a01e9db412'),'execution-instance'))"));

        // 4. Digest must survive a Python round trip.
        const string content = "{\"operation\":\"script\",\"program\":\"pwsh\",\"workdir\":\"C:\\\\w\",\"args\":[\"a\",\"b\"],\"script\":\"C:\\\\w\\\\s.ps1\"}";
        Check("digest", RecordJson.Digest(JsonNode.Parse(content)!),
            Python("import hashlib,json,sys;print(hashlib.sha256(json.dumps(json.loads(sys.argv[1]),ensure_ascii=True,sort_keys=True,separators=(',',':')).encode()).hexdigest())", content));

        // 5. Redaction parity with output_store.redact_line.
        foreach (string line in new[] { "PASSWORD = hunter2", "Authorization: Bearer abc.def.ghi",
            "token sk-abcdefghij1234567890", "ghp_0123456789abcdefghijkl", "plain line", "cookie: session=1" })
            Check($"redact.{line[..Math.Min(20, line.Length)]}", OutputCapture.RedactLine(line).TrimEnd('\n'),
                Python("import sys;from output_store import redact_line;print(redact_line(sys.argv[1]).rstrip('\\n'))", line));

        CheckNumbers();
        CheckCleanup();
        CheckCompletion();
        CheckCleanupFailures();
        CheckShortReads();
        Console.WriteLine(failures == 0 ? "ALL PASS" : failures + " FAILURES");
        return failures == 0 ? 0 : 1;
    }

    private static string Text(JsonNode node) => RecordJson.Utf8.GetString(RecordJson.Packed(node));

    private static void Check(string label, string actual, string expected)
    {
        bool ok = actual == expected;
        if (!ok) failures++;
        Console.WriteLine((ok ? "PASS " : "FAIL ") + label + ": " + actual + (ok ? "" : " != " + expected));
    }

    private static string Python(string code, string? arg = null)
    {
        RecordJson.Require(File.Exists(Path.Combine(Root, "server.py")), "conformance_requires_repository_cwd");
        var psi = new ProcessStartInfo(PythonExe)
        {
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false,
            CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden, WorkingDirectory = Root
        };
        foreach (string argument in new[] { "-I", "-X", "utf8", "-c",
            "import sys;sys.path.insert(0," + JsonValue.Create(Root)!.ToJsonString() + ")\n" + code })
            psi.ArgumentList.Add(argument);
        if (arg is not null) psi.ArgumentList.Add(arg);
        using var process = Process.Start(psi)!;
        string output = process.StandardOutput.ReadToEnd().Trim();
        string error = process.StandardError.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0) throw new Exception("python failed: " + error);
        return output;
    }

    private static void CheckNumbers()
    {
        var values = new List<double> { -0.0, 0.0, 1.0, -1.0, double.Epsilon, double.MaxValue, double.MinValue };
        var random = new Random(20260915);
        byte[] bits = new byte[8];
        while (values.Count < 263)
        {
            random.NextBytes(bits);
            double value = BitConverter.ToDouble(bits);
            if (double.IsFinite(value)) values.Add(value);
        }
        var raw = new JsonArray(values.Select(value => (JsonNode?)JsonValue.Create(value.ToString("R", CultureInfo.InvariantCulture))).ToArray());
        var expected = JsonNode.Parse(Python("import json;print(json.dumps([json.dumps(float(s)) for s in json.loads(sys.argv[1])]))", Text(raw)))!.AsArray();
        for (int index = 0; index < values.Count; index++)
        {
            Check("created-double." + index, Text(JsonValue.Create(values[index])!), expected[index].String());
            Check("parsed-double." + index, Text(JsonNode.Parse(expected[index].String())!), expected[index].String());
        }
    }

    private static void CheckCompletion()
    {
        string directory = Path.Combine(Root, ".codex-command-records", "csharp-completion-" + Guid.NewGuid());
        Directory.CreateDirectory(directory);
        foreach (string terminal in new[] { "exited", "timed_out", "cancelled" })
        foreach (bool failWrite in new[] { false, true })
        {
            string label = $"completion.{terminal}.{failWrite}";
            string path = Path.Combine(directory, terminal + "-" + failWrite + ".json");
            var result = new JsonObject { ["state"] = "running" };
            RecordJson.Save(path, result);
            int businessFailures = 0, writes = 0;
            var writeError = new IOException("final_write_failed");
            Exception? observed = null;
            try
            {
                ExecutionCleanup.Complete(() =>
                {
                    result["state"] = terminal;
                    result["operation_result"] = new JsonObject { ["acceptable_exit"] = terminal == "exited" ? true : null };
                    result["subgoal"] = new JsonObject { ["status"] = terminal == "exited" ? "confirmed" : "unknown" };
                    return Task.CompletedTask;
                }, error =>
                {
                    businessFailures++;
                    result["state"] = "tool_error";
                    return Task.CompletedTask;
                }, () =>
                {
                    writes++;
                    if (failWrite) throw writeError;
                    RecordJson.Save(path, result);
                }).GetAwaiter().GetResult();
            }
            catch (Exception error) { observed = error; }
            Check(label + ".exception", ReferenceEquals(observed, failWrite ? writeError : null).ToString(), "True");
            Check(label + ".business-failures", businessFailures.ToString(), "0");
            Check(label + ".writes", writes.ToString(), "1");
            Check(label + ".state", result["state"].String(), terminal);
            Check(label + ".acceptable", Text(result["operation_result"]!["acceptable_exit"]!), terminal == "exited" ? "true" : "null");
            Check(label + ".subgoal", result["subgoal"]!["status"].String(), terminal == "exited" ? "confirmed" : "unknown");
            Check(label + ".stored", RecordJson.Read(path)["state"].String(), failWrite ? "running" : terminal);
        }
        int handled = 0, finalWrites = 0;
        var businessError = new IOException("business_failed");
        ExecutionCleanup.Complete(() => Task.FromException(businessError), error =>
        {
            Check("completion.business-error", ReferenceEquals(error, businessError).ToString(), "True");
            handled++;
            return Task.CompletedTask;
        }, () => finalWrites++).GetAwaiter().GetResult();
        Check("completion.business-handler", handled.ToString(), "1");
        Check("completion.no-success-write", finalWrites.ToString(), "0");
    }

    private static void CheckCleanupFailures()
    {
        string directory = Path.Combine(Root, ".codex-command-records", "csharp-cleanup-failures-" + Guid.NewGuid());
        Directory.CreateDirectory(directory);
        foreach (string kind in new[] { "completed", "handled", "unhandled" })
        foreach (bool failWrite in new[] { false, true })
        {
            string label = $"cleanup-failure.{kind}.{failWrite}";
            string path = Path.Combine(directory, kind + "-" + failWrite + ".json");
            var result = new JsonObject { ["state"] = "tool_error", ["error"] = ExecutionRecords.Error(new IOException("primary_failure")) };
            Exception? cleanupError = kind == "completed" ? null : kind == "handled"
                ? new TimeoutException("cleanup_timeout") : new IndexOutOfRangeException("cleanup_unhandled");
            var writeError = new IOException("password=synthetic-value");
            Exception? observed = null;
            int writes = 0;
            try
            {
                ExecutionCleanup.PersistFailure(result, () => cleanupError is null ? Task.CompletedTask : Task.FromException(cleanupError), () =>
                {
                    writes++;
                    if (failWrite) throw writeError;
                    RecordJson.Save(path, result);
                }).GetAwaiter().GetResult();
            }
            catch (Exception error) { observed = error; }
            Check(label + ".writes", writes.ToString(), "1");
            Check(label + ".primary", result["error"]!["reason"].String(), "primary_failure");
            Check(label + ".stored", File.Exists(path).ToString(), (!failWrite).ToString());
            if (failWrite)
            {
                Check(label + ".failure-type", (observed is ExecutionPersistenceFailure).ToString(), "True");
                var detail = ExecutionRecords.Error(observed!);
                Check(label + ".reason", detail["reason"].String(), "execution_state_persistence_failed");
                Check(label + ".preserved-primary", detail["primary_error"]!["reason"].String(), "primary_failure");
                Check(label + ".cleanup", (detail["cleanup_error"] is not null).ToString(), (cleanupError is not null).ToString());
                Check(label + ".redaction", detail["persistence_error"]!["reason"].String().Contains("[REDACTED").ToString(), "True");
                Check(label + ".no-secret", Text(detail).Contains("synthetic-value").ToString(), "False");
                Check(label + ".inner", (cleanupError is null ? ReferenceEquals(observed!.InnerException, writeError)
                    : observed!.InnerException is AggregateException aggregate && ReferenceEquals(aggregate.InnerExceptions[0], cleanupError)
                        && ReferenceEquals(aggregate.InnerExceptions[1], writeError)).ToString(), "True");
            }
            else
            {
                Check(label + ".escape", ReferenceEquals(observed, kind == "unhandled" ? cleanupError : null).ToString(), "True");
                Check(label + ".stored-primary", RecordJson.Read(path)["error"]!["reason"].String(), "primary_failure");
            }
        }
    }

    private sealed class ShortReadStream(byte[] bytes) : MemoryStream(bytes)
    {
        public override int Read(Span<byte> buffer) => base.Read(buffer[..Math.Min(7, buffer.Length)]);
    }

    private static void CheckShortReads()
    {
        byte[] input = new byte[65545];
        Array.Fill(input, (byte)'x');
        input[0] = (byte)'\n'; input[65535] = 0xff;
        using var source = new ShortReadStream(input);
        byte[] block = new byte[65536];
        int count = TextRangeReader.ReadBlock(source, block);
        Check("short-read.full-block", count.ToString(), "65536");
        Check("short-read.contents", block.AsSpan().SequenceEqual(input.AsSpan(0, 65536)).ToString(), "True");
        Check("short-read.warning-byte", block[^1].ToString(), "255");
        count = TextRangeReader.ReadBlock(source, block);
        Check("short-read.final-block", count.ToString(), "9");
        Check("short-read.final-contents", block.AsSpan(0, count).SequenceEqual(input.AsSpan(65536)).ToString(), "True");
        Check("short-read.eof", TextRangeReader.ReadBlock(source, block).ToString(), "0");
    }

    private static void CheckCleanup()
    {
        string directory = Path.Combine(Root, ".codex-command-records", "csharp-cleanup-" + Guid.NewGuid());
        Directory.CreateDirectory(directory);
        foreach (string kind in new[] { "timeout", "io", "completed" })
        {
            var result = new JsonObject { ["state"] = "tool_error",
                ["error"] = new JsonObject { ["kind"] = "OSError", ["reason"] = "primary_failure" },
                ["process"] = new JsonObject { ["exit_code"] = null } };
            string path = Path.Combine(directory, kind + ".json");
            int writes = 0;
            Task Cleanup() => kind switch
            {
                "timeout" => Task.FromException(new TimeoutException("cleanup_timed_out")),
                "io" => Task.FromException(new IOException("cleanup_io_failure")),
                _ => Task.CompletedTask
            };
            ExecutionCleanup.PersistFailure(result, Cleanup, () => { RecordJson.Save(path, result); writes++; }).GetAwaiter().GetResult();
            var stored = RecordJson.Read(path);
            Check("cleanup." + kind + ".persist", writes.ToString(), "1");
            Check("cleanup." + kind + ".state", stored["state"].String(), "tool_error");
            Check("cleanup." + kind + ".primary", stored["error"]!["reason"].String(), "primary_failure");
            Check("cleanup." + kind + ".exit", Text(stored["process"]!["exit_code"]!), "null");
            Check("cleanup." + kind + ".secondary", (stored["cleanup_error"] is not null).ToString(), (kind != "completed").ToString());
        }
    }
}
#endif
