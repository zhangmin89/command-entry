#if CONFORMANCE
// Cross-language conformance harness (Python vs C#), compiled only with
// -p:DefineConstants=CONFORMANCE. Not part of the shipped binary.
using System.Diagnostics;
using System.Text.Json.Nodes;

namespace CommandEntry;

internal static class Conformance
{
    private const string PythonExe = @"C:\Users\zhang\AppData\Local\Python\pythoncore-3.14-64\python.exe";
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

        // 2. Key ordering: Python sorts str by UTF-16 code units; U+E000 < surrogate D83D.
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
        string script = Path.Combine(Path.GetTempPath(), "ce-conformance-" + Guid.NewGuid().ToString("N") + ".py");
        File.WriteAllText(script, "import sys;sys.path.insert(0,r'c:\\Code\\command-entry')\n" + code);
        try
        {
            var psi = new ProcessStartInfo(PythonExe) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
            psi.ArgumentList.Add(script);
            if (arg is not null) psi.ArgumentList.Add(arg);
            psi.WorkingDirectory = Directory.Exists(@"c:\Code\command-entry") ? @"c:\Code\command-entry" : AppContext.BaseDirectory;
            using var process = Process.Start(psi)!;
            string output = process.StandardOutput.ReadToEnd().Trim();
            string error = process.StandardError.ReadToEnd();
            process.WaitForExit();
            if (process.ExitCode != 0) throw new Exception("python failed: " + error);
            return output;
        }
        finally { File.Delete(script); }
    }
}
#endif
