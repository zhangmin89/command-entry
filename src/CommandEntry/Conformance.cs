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
