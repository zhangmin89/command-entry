using System.Text.Json.Nodes;
using CommandEntry;
using static CommandEntry.RecordJson;

namespace CommandEntry.Tests;

internal static class ScriptTests
{
    [Case]
    private static void ExternalInterpretersPreserveProcessContract()
    {
        foreach (string language in new[] { "powershell", "javascript", "python" })
        {
            using var f = new Fixture();
            if (language == "javascript")
            {
                f.Policy["programs"].Object()[language] = Read(Path.Combine(TestRunner.Root, "policy.json"))["programs"]!["node"]?.Copy();
                f.Restart();
            }
            string[] names = ["a b", "中文😀", "a'b", "&|%$()`", ""];
            byte[] bytes = [0, 10, 13, 255, 128, 65];
            string source = language switch
            {
                "powershell" => """
                    param([string[]]$Names,[hashtable]$Payload)
                    Set-StrictMode -Version Latest
                    $ErrorActionPreference = 'Stop'
                    $buffer = [IO.MemoryStream]::new()
                    [Console]::OpenStandardInput().CopyTo($buffer)
                    @{args=$Names;stdin=[Convert]::ToBase64String($buffer.ToArray());cwd=(Get-Location).Path;
                      root=$PSScriptRoot;script=$PSCommandPath;payload=$Payload;
                      adapterVariable=[Environment]::GetEnvironmentVariable('COMMAND_ENTRY_POWERSHELL_REQUEST')} | ConvertTo-Json -Depth 8 -Compress
                    [Console]::Error.Write('stderr-中文')
                    exit 7
                    """,
                "javascript" => """
                    const fs = require('node:fs');
                    console.log(JSON.stringify({args:process.argv.slice(2),stdin:fs.readFileSync(0).toString('base64'),cwd:process.cwd()}));
                    process.stderr.write('stderr-中文');
                    process.exitCode = 7;
                    """,
                _ => """
                    import sys,json,base64,os
                    print(json.dumps({'args':sys.argv[1:],'stdin':base64.b64encode(sys.stdin.buffer.read()).decode(),'cwd':os.getcwd()}))
                    sys.stderr.write('stderr-中文')
                    sys.exit(7)
                    """
            };
            string extension = language switch { "powershell" => ".ps1", "javascript" => ".cjs", _ => ".py" };
            string script = f.Write("用户 ' $` probe" + extension, source), input = f.FilePath("input.bin");
            File.WriteAllBytes(input, bytes);
            var expected = new JsonObject { ["args"] = new JsonArray(names.Select(name => (JsonNode?)JsonValue.Create(name)).ToArray()),
                ["stdin"] = Convert.ToBase64String(bytes), ["cwd"] = f.DirectoryPath };
            var form = f.Script(script, language); form["stdin_file"] = input;
            if (language == "powershell")
            {
                var payload = new JsonObject { ["flag"] = true, ["count"] = 3, ["values"] = new JsonArray("", null) };
                string parameters = f.FilePath("参数 ' $` file.json");
                WriteNew(parameters, new JsonObject { ["Names"] = expected["args"]?.Copy(), ["Payload"] = payload.Copy() });
                form["parameters_file"] = parameters;
                expected["root"] = f.DirectoryPath; expected["script"] = script; expected["payload"] = payload;
                expected["adapterVariable"] = null;
            }
            else form["args"] = expected["args"]?.Copy();
            var state = f.Execute(form); Check.Equal("exited", state["state"].String());
            Check.Equal(7L, state["process"]!["exit_code"].Integer("exit"));
            Check.True(!state["operation_result"]!["acceptable_exit"].IsTrue());
            Check.Json(expected, JsonNode.Parse(f.Output(state["execution_id"].String())));
            Check.Equal("stderr-中文", f.Output(state["execution_id"].String(), "stderr"));
            var stored = Read(Path.Combine(state["record_dir"].String(), "result.json"));
            Check.Equal(BusinessPaths.Resolve(f.Policy["programs"]![language]!["path"].String(), "file"), stored["argv"]![0].String());
        }
    }

    [Case]
    private static void EmbeddedPowerShellErrorsRemainTextAndInvalidSourceDoesNotExecute()
    {
        using var f = new Fixture();
        string script = f.Write("throw ' $` probe.ps1", "param()\nSet-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\nthrow 'embedded-adapter-test'\n");
        var failed = f.Execute(f.Script(script)); Check.Equal("exited", failed["state"].String());
        Check.Equal(1L, failed["process"]!["exit_code"].Integer("exit"));
        string stderr = f.Output(failed["execution_id"].String(), "stderr");
        Check.Contains("embedded-adapter-test", stderr); Check.True(!stderr.Contains("#< CLIXML"));
        script = f.Write("broken ' $` probe.ps1", "Set-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n[IO.File]::WriteAllText('must-not-exist.txt','bad')\nif ( {\n");
        var invalid = f.Execute(f.Script(script)); Check.Equal("exited", invalid["state"].String());
        Check.Equal(1L, invalid["process"]!["exit_code"].Integer("exit"));
        Check.True(!invalid["operation_result"]!["acceptable_exit"].IsTrue());
        stderr = f.Output(invalid["execution_id"].String(), "stderr");
        Check.Contains(Path.GetFileName(script), stderr); Check.True(!stderr.Contains("#< CLIXML"));
        Check.True(!File.Exists(f.FilePath("must-not-exist.txt")));
        Check.True(File.Exists(Path.Combine(invalid["record_dir"].String(), "business-process.json")));
    }

    [Case]
    private static void PowershellSplattingKeepsArraysAndFullParameterNames()
    {
        using var f = new Fixture();
        string script = f.Write("参数 probe.ps1", "param([string[]]$Names,[string]$Message)\nSet-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n@{names=$Names;message=$Message} | ConvertTo-Json -Compress\n");
        string parameters = f.FilePath("parameters.json");
        var expected = new JsonObject { ["names"] = new JsonArray("a b", "中文😀", "x\\\"y"), ["message"] = "&|%$()`" };
        WriteNew(parameters, new JsonObject { ["Names"] = expected["names"]?.Copy(), ["Message"] = expected["message"]?.Copy() });
        var form = f.Script(script); form["parameters_file"] = parameters;
        var state = f.Execute(form); Check.Equal("exited", state["state"].String()); Check.True(state["operation_result"]!["acceptable_exit"].IsTrue());
        Check.Json(expected, JsonNode.Parse(f.Output(state["execution_id"].String())));
        Save(parameters, new JsonObject { ["Na"] = new JsonArray("wrong") });
        var bad = f.Execute(form); Check.Equal("exited", bad["state"].String()); Check.True(!bad["operation_result"]!["acceptable_exit"].IsTrue());
        Check.Contains("Unknown or abbreviated parameter name", f.Output(bad["execution_id"].String(), "stderr"));
        var arguments = f.Script(script); arguments["args"] = new JsonArray("-Names", "not-splatted");
        var rejected = f.Execute(arguments); Check.Equal("rejected", rejected["state"].String()); Check.Contains("powershell_requires_parameters_file", rejected["error"]!["reason"].String());
    }

    [Case]
    private static void RuntimeSyntaxErrorsAreRetainedAndBatchNeverRuns()
    {
        using var f = new Fixture();
        f.Policy["programs"].Object()["javascript"] = Read(Path.Combine(TestRunner.Root, "policy.json"))["programs"]!["node"]?.Copy();
        f.Restart();
        foreach (var (language, name, code) in new[]
        {
            ("powershell", "broken.ps1", "if ( {"),
            ("python", "broken.py", "if syntax broken\n"),
            ("python", "compile-error.py", "return 1\n"),
            ("javascript", "broken.cjs", "const value = ;\n")
        })
        {
            string script = f.Write(name, code); var state = f.Execute(f.Script(script, language));
            Check.Equal("exited", state["state"].String());
            Check.Equal(1L, state["process"]!["exit_code"].Integer("exit"));
            Check.True(!state["operation_result"]!["acceptable_exit"].IsTrue());
            string stderr = f.Output(state["execution_id"].String(), "stderr");
            Check.Contains(name, stderr);
            if (language is "python" or "javascript") Check.Contains("SyntaxError", stderr);
            var stored = Read(Path.Combine(state["record_dir"].String(), "result.json"));
            Check.Equal("not_applicable", stored["syntax"]!["status"].String());
            Check.True(File.Exists(Path.Combine(state["record_dir"].String(), "business-process.json")));
        }
        string batch = f.Write("batch.cmd", "@echo SHOULD_NOT_RUN\n"); f.Policy["programs"].Object()["batch"] = new JsonObject { ["kind"] = "native", ["path"] = batch }; f.Restart();
        var form = f.Form("location"); form["program"] = "batch"; var rejected = f.Execute(form);
        Check.Equal("rejected", rejected["state"].String()); Check.Contains("native_requires_exe", rejected["error"]!["reason"].String());
        Check.True(!File.Exists(Path.Combine(rejected["record_dir"].String(), "business-process.json")));
    }

    [Case]
    private static void UserPythonWorkStillUsesConfiguredInterpreter()
    {
        using var f = new Fixture(); string path = f.Write("user-work.py", "from pathlib import Path\nPath('marker.txt').write_text('once')\nprint('user-work')\n");
        var state = f.Execute(f.Script(path, "python")); Check.Equal("exited", state["state"].String()); Check.Equal(0L, state["process"]!["exit_code"].Integer("exit"));
        Check.Equal("user-work\n", f.Output(state["execution_id"].String())); Check.Equal("once", File.ReadAllText(f.FilePath("marker.txt")));
        Check.True(!Directory.Exists(f.FilePath("__pycache__")));
        string unit = f.Write("test_user.py", "import unittest\nclass UserTests(unittest.TestCase):\n def test_value(self):\n  self.assertEqual(2+3,5)\n");
        var form = new JsonObject { ["operation"] = "python_unittest", ["program"] = "python", ["workdir"] = f.DirectoryPath, ["args"] = new JsonArray("test_user", "-v"), ["input_paths"] = new JsonArray(unit) };
        state = f.Execute(form); Check.Equal("exited", state["state"].String()); Check.Equal(0L, state["process"]!["exit_code"].Integer("exit"));
        Check.Contains("Ran 1 test", f.Output(state["execution_id"].String(), "stderr"));
    }

    [Case]
    private static async Task OnlyBashPlanningStartsAnInterpreter()
    {
        foreach (var (language, extension) in new[] { ("powershell", ".ps1"), ("javascript", ".cjs"), ("python", ".py"), ("bash", ".sh") })
        {
            using var f = new Fixture();
            // An existing file that cannot start proves whether planning launches the interpreter.
            string executable = f.Write("not-executable.exe", "Not a Windows executable");
            f.Policy["programs"].Object()[language] = new JsonObject { ["kind"] = language, ["path"] = executable };
            string script = f.Write("invalid" + extension, "if ( {\n");
            var request = f.Script(script, language); request["cwd"] = f.DirectoryPath;
            using var locks = new FileBindings();
            if (language == "bash")
                Check.Throws<System.ComponentModel.Win32Exception>(() => ExecutionPlan.Create(request, f.Policy, locks, f.DirectoryPath).GetAwaiter().GetResult());
            else
            {
                var plan = await ExecutionPlan.Create(request, f.Policy, locks, f.DirectoryPath);
                Check.Equal(executable, plan.Executable);
                Check.Equal("not_applicable", plan.Syntax["status"].String());
                Check.True(locks.Bindings.ContainsKey(script));
            }
        }
    }

    [Case]
    private static void NewlyAddedUnboundInputDoesNotAuthorizeRetry()
    {
        using var f = new Fixture(); string script = f.Write("unchanged.ps1", "param()\nSet-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\nWrite-Output 'same'\n");
        var form = f.Script(script); var first = f.Execute(form); Check.Equal("exited", first["state"].String());
        var business = f.Envelope(first["execution_id"].String())["business"].Object().Copy().Object();
        business["attempt"] = 1; business["previous_request"] = first["request_id"]?.Copy(); business["input_paths"] = new JsonArray(f.Write("extra.txt", "new only"));
        string request = f.FilePath("retry-request.json"); WriteNew(request, new JsonObject { ["business"] = business, ["fingerprint"] = RequestDigest(RequestShape.Shape(business)) });
        var result = Fixture.Run(TestRunner.Server, ["run", "--request", request, "--policy", f.PolicyPath]);
        Check.Equal(125, result.Exit); var rejected = JsonNode.Parse(result.Out).Object(); Check.Equal("rejected", rejected["state"].String());
        Check.Contains("verified_changed_conditions_required", rejected["error"]!["reason"].String());
    }

    [Case]
    private static async Task DotnetEnvironmentCheckIsLimitedToCliInfo()
    {
        using var f = new Fixture(); string fakeDotnet = f.Write("dotnet.exe", "plan-only; never executed");
        f.Policy["programs"].Object()["dotnet"] = new JsonObject { ["kind"] = "native", ["path"] = fakeDotnet };
        string? before = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");
        try
        {
            Environment.SetEnvironmentVariable("PROCESSOR_ARCHITECTURE", null);
            using var locks = new FileBindings();
            foreach (string[] arguments in new[] { new[] { "--version" }, new[] { "app.dll", "--info" } })
            {
                var request = new JsonObject { ["operation"] = "native", ["program"] = "dotnet", ["args"] = new JsonArray(arguments.Select(value => (JsonNode?)JsonValue.Create(value)).ToArray()) };
                var plan = await ExecutionPlan.Create(request, f.Policy, locks, f.DirectoryPath); Check.Equal(string.Join('|', arguments), string.Join('|', plan.Arguments));
            }
            var info = new JsonObject { ["operation"] = "native", ["program"] = "dotnet", ["args"] = new JsonArray("--info") };
            Check.Throws<InvalidRequest>(() => ExecutionPlan.Create(info, f.Policy, locks, f.DirectoryPath).GetAwaiter().GetResult(), "dotnet_environment_missing: PROCESSOR_ARCHITECTURE");
            Check.True(Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE") is null);
            Environment.SetEnvironmentVariable("PROCESSOR_ARCHITECTURE", "AMD64"); var allowed = await ExecutionPlan.Create(info, f.Policy, locks, f.DirectoryPath); Check.Equal("--info", allowed.Arguments.Single());
        }
        finally { Environment.SetEnvironmentVariable("PROCESSOR_ARCHITECTURE", before); }
    }

    [Case]
    private static void MissingProgramHealthIsObservationOnly()
    {
        using var f = new Fixture(); string missing = f.FilePath("ghost.exe");
        f.Policy["programs"].Object()["ghost"] = new JsonObject { ["kind"] = "native", ["path"] = missing }; f.Restart();
        string hash = FileHash(f.PolicyPath); Check.True(!File.Exists(missing));
        var startup = File.ReadLines(f.FilePath("logs/server-events.jsonl")).Select(line => JsonNode.Parse(line).Object()).Last(item => item["kind"].Text() == "startup");
        Check.True(startup["program_health"]!["missing"].Array().Any(item => item.Text() == "ghost"));
        Check.Equal(0, startup["program_health"]!["healed"].Array().Count); Check.Equal(hash, FileHash(f.PolicyPath));
        var form = f.Form("location"); form["program"] = "unconfigured";
        var rejected = f.Client.Raw("start_operation", form); Check.True(rejected["isError"].IsTrue());
        var events = File.ReadLines(f.FilePath("logs/server-events.jsonl")).Select(line => JsonNode.Parse(line).Object());
        Check.True(events.Any(item => item["kind"].Text() == "rejected" && item["reason"].Text() == "program_not_configured"));
    }
}
