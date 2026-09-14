using System.Diagnostics;
using System.Text.Json.Nodes;
using static CommandEntry.RecordJson;

namespace CommandEntry;

internal sealed record ExecutionPlan(string Executable, string[] Arguments, int Budget, int OutputQuota, JsonObject Syntax)
{
    internal static async Task<ExecutionPlan> Create(JsonObject request, JsonObject policy, FileBindings locks, string directory)
    {
        foreach (string name in new[] { "input_paths", "required_tools" })
            foreach (var value in request.ArrayOrEmpty(name)) locks.Add(BusinessPaths.Resolve(value.String(), "file"));
        if (request.ContainsKey("stdin_file")) locks.Add(BusinessPaths.Resolve(request["stdin_file"].String(), "file"));
        string operation = request["operation"].String();
        var options = RequestShape.Options(request, policy);
        var program = policy["programs"]?[request["program"].String()].Object("program_not_configured")
            ?? throw new InvalidRequest("program_not_configured");
        string executable = BusinessPaths.Resolve(program["path"].String(), "file");
        string[] arguments = request.ArrayOrEmpty("args").Select(v => v.String()).ToArray();
        JsonObject syntax = new() { ["status"] = "not_applicable" };
        if (operation == "native")
        {
            Require(program["kind"].Text() == "native", "interpreter_requires_explicit_script_or_module_operation");
            Require(executable.EndsWith(".exe", StringComparison.OrdinalIgnoreCase), "native_requires_exe_batch_files_route_through_cmd");
            if (Path.GetFileName(executable).Equals("dotnet.exe", StringComparison.OrdinalIgnoreCase) && arguments.SequenceEqual(["--info"]))
                Require(!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE")), "dotnet_environment_missing: PROCESSOR_ARCHITECTURE");
        }
        else if (operation == "python_unittest")
        {
            Require(program["kind"].Text() == "python", "python_runtime_required");
            arguments = ["-X", "utf8", "-m", "unittest", .. arguments];
        }
        else
        {
            string language = request["language"].String();
            Require(program["kind"].Text() == language, "interpreter_language_mismatch");
            string script = BusinessPaths.Resolve(request["script"].String(), "file");
            locks.Add(script);
            string extension = Path.GetExtension(script).ToLowerInvariant();
            Require(language switch
            {
                "python" => extension == ".py", "powershell" => extension == ".ps1",
                "javascript" => extension is ".js" or ".mjs" or ".cjs" or ".ts" or "", "bash" => extension == ".sh", _ => false
            }, "script_form_not_supported");
            if (language == "powershell")
            {
                Require(arguments.Length == 0, "powershell_requires_parameters_file");
                var invocation = new JsonObject { ["mode"] = "script", ["language"] = language,
                    ["interpreter"] = executable, ["script"] = script, ["cwd"] = request["cwd"]?.Copy() };
                if (request.ContainsKey("parameters_file"))
                {
                    locks.Add(BusinessPaths.Resolve(request["parameters_file"].String(), "file"));
                    _ = Read(request["parameters_file"].String());
                    invocation["parameters_file"] = request["parameters_file"]?.Copy();
                }
                string invokeFile = Path.Combine(directory, "powershell-invocation.json");
                WriteNew(invokeFile, invocation); locks.Add(invokeFile);
                arguments = ["-NoProfile", "-File", Path.Combine(AppContext.BaseDirectory, "invoke.ps1"), "-RequestPath", invokeFile];
            }
            else
            {
                Require(!request.ContainsKey("parameters_file"), "parameters_file_only_for_powershell");
                arguments = language == "python" ? ["-X", "utf8", script, .. arguments] : [script, .. arguments];
            }
            syntax = await CheckSyntax(executable, language, script, request["cwd"].String());
            Require(syntax["status"].Text() == "passed", "script_syntax_check_failed: " + syntax["stderr"]?["text"].Text());
        }
        foreach (var pair in request.ObjectOrEmpty("expected_versions"))
        {
            string path = BusinessPaths.Resolve(pair.Key, "file"); locks.Add(path);
            Require(locks.Bindings[path].Text() == pair.Value.Text(), "declared_content_version_changed");
        }
        return new(executable, arguments, options.Int("run_seconds", 0), options.Int("output_quota_bytes", 0), syntax);
    }

    private static async Task<JsonObject> CheckSyntax(string executable, string language, string script, string cwd)
    {
        string[] arguments = language switch
        {
            "python" => ["-I", "-X", "utf8", Path.Combine(AppContext.BaseDirectory, "check_python.py"), script],
            "powershell" => ["-NoProfile", "-File", Path.Combine(AppContext.BaseDirectory, "check_powershell.ps1"), "-ScriptPath", script],
            "javascript" => ["--check", script], "bash" => ["-n", script], _ => throw new InvalidRequest("unsupported_language")
        };
        using var process = Process.Start(WindowsProcess.StartInfo(executable, arguments, cwd))!;
        process.StandardInput.Close();
        var stdout = DrainSyntax(process.StandardOutput.BaseStream);
        var stderr = DrainSyntax(process.StandardError.BaseStream);
        try { await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (TimeoutException) { process.Kill(); await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10)); }
        return new() { ["status"] = process.ExitCode == 0 ? "passed" : "failed", ["exit_code"] = process.ExitCode,
            ["stdout"] = await stdout.WaitAsync(TimeSpan.FromSeconds(10)), ["stderr"] = await stderr.WaitAsync(TimeSpan.FromSeconds(10)) };
    }

    private static async Task<JsonObject> DrainSyntax(Stream stream)
    {
        using (stream)
        using (var retained = new MemoryStream())
        {
            byte[] buffer = new byte[8192]; long total = 0; int count;
            while ((count = await stream.ReadAsync(buffer)) != 0)
            {
                total += count;
                retained.Write(buffer, 0, Math.Min(count, 8192 - (int)retained.Length));
            }
            // Syntax diagnostics are bounded to 8192 bytes before redaction.
            string text = string.Concat(TextCodec.Lines(System.Text.Encoding.UTF8.GetString(retained.ToArray())).Select(OutputCapture.RedactLine));
            if (text.Contains("PRIVATE KEY-----")) text = "[REDACTED PRIVATE KEY]";
            return new() { ["text"] = text, ["bytes"] = total, ["truncated"] = total > retained.Length, ["capture_complete"] = true };
        }
    }
}
