using System.Diagnostics;
using System.Text.Json.Nodes;
using CommandEntry;
using static CommandEntry.RecordJson;

namespace CommandEntry.Tests;

internal sealed class McpClient : IDisposable
{
    internal Process Process { get; }
    internal JsonObject Initialization { get; }
    private readonly Task<string> stderr;
    private int sequence;
    private bool disposed;

    internal McpClient(string policy, string? binding = null, string? executable = null)
    {
        string[] args = binding is null ? ["--policy", policy] : ["--policy", policy, "--binding", binding];
        Process = System.Diagnostics.Process.Start(WindowsProcess.StartInfo(executable ?? TestRunner.Server, args, TestRunner.Root))!;
        stderr = Process.StandardError.ReadToEndAsync();
        Initialization = Rpc("initialize", new JsonObject { ["protocolVersion"] = "2025-06-18", ["capabilities"] = new JsonObject(),
            ["clientInfo"] = new JsonObject { ["name"] = "csharp-contract-tests", ["version"] = "1" } });
        Send(new JsonObject { ["jsonrpc"] = "2.0", ["method"] = "notifications/initialized" });
    }

    private void Send(JsonObject message)
    {
        Process.StandardInput.WriteLine(Utf8.GetString(Packed(message)));
        Process.StandardInput.Flush();
    }

    internal JsonObject Rpc(string method, JsonObject parameters)
    {
        int id = ++sequence;
        Send(new JsonObject { ["jsonrpc"] = "2.0", ["id"] = id, ["method"] = method, ["params"] = parameters.Copy() });
        while (true)
        {
            string? line = Process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(60)).GetAwaiter().GetResult();
            if (line is null) throw new Exception("server EOF: " + stderr.GetAwaiter().GetResult());
            var message = JsonNode.Parse(line).Object();
            if (message["id"]?.ToJsonString() != id.ToString()) continue;
            Check.True(!message.ContainsKey("error"), message.ToJsonString());
            return message["result"].Object();
        }
    }

    internal JsonObject Raw(string name, JsonObject arguments) => Rpc("tools/call", new JsonObject { ["name"] = name, ["arguments"] = arguments.Copy() });
    internal JsonObject Call(string name, JsonObject arguments)
    {
        var result = Raw(name, arguments);
        Check.True(!result["isError"].IsTrue(), result.ToJsonString());
        return result["structuredContent"].Object();
    }
    internal (int Exit, string Error) CloseInput()
    {
        var remainingOutput = Process.StandardOutput.ReadToEndAsync();
        Process.StandardInput.Close();
        Check.True(Process.WaitForExit(10000), "MCP server did not exit after stdin closed");
        _ = remainingOutput.GetAwaiter().GetResult();
        return (Process.ExitCode, stderr.GetAwaiter().GetResult());
    }

    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        if (!Process.HasExited)
        {
            Process.StandardInput.Close();
            if (!Process.WaitForExit(20000)) { Process.Kill(); Check.True(Process.WaitForExit(10000)); }
        }
        _ = stderr.GetAwaiter().GetResult();
        Process.Dispose();
    }
}

internal sealed class Fixture : IDisposable
{
    internal string DirectoryPath { get; } = Path.Combine(TestRunner.Root, ".codex-command-records", "csharp-test-" + Guid.NewGuid());
    internal string PolicyPath => Path.Combine(DirectoryPath, "policy.json");
    internal JsonObject Policy { get; }
    internal McpClient Client { get; private set; }
    internal string Serve => Path.Combine(DirectoryPath, "serve-input");
    internal Fixture()
    {
        Directory.CreateDirectory(DirectoryPath);
        Policy = Read(Path.Combine(TestRunner.Root, "policy.json"));
        Policy["working_roots"] = new JsonArray(DirectoryPath); Policy["read_roots"] = null;
        Policy["serve_root"] = Serve; Policy["log_root"] = Path.Combine(DirectoryPath, "logs");
        Policy["cancel_grace_seconds"] = 1; Policy["cancel_confirm_seconds"] = 3;
        Policy["programs"] = new JsonObject
        {
            ["probe"] = new JsonObject { ["kind"] = "native", ["path"] = TestRunner.ProbeExe },
            ["server"] = new JsonObject { ["kind"] = "native", ["path"] = TestRunner.Server },
            ["powershell"] = new JsonObject { ["kind"] = "powershell", ["path"] = Policy["powershell"]?.Copy() },
            ["python"] = new JsonObject { ["kind"] = "python", ["path"] = Policy["python"]?.Copy() }
        };
        WriteNew(PolicyPath, Policy);
        Client = new(PolicyPath);
    }
    internal string FilePath(string name) => Path.Combine(DirectoryPath, name);
    internal string Write(string name, string text)
    { string path = FilePath(name); File.WriteAllText(path, text, Utf8); return path; }
    internal JsonObject Form(params string[] args) => new()
    {
        ["operation"] = "native", ["program"] = "probe", ["workdir"] = DirectoryPath,
        ["args"] = new JsonArray(new[] { "probe" }.Concat(args).Select(value => (JsonNode?)JsonValue.Create(value)).ToArray())
    };
    internal JsonObject Script(string path, string language = "powershell") => new()
    { ["operation"] = "script", ["program"] = language, ["language"] = language, ["script"] = path, ["workdir"] = DirectoryPath };
    internal JsonObject Start(JsonObject form) => Client.Call("start_operation", form);
    internal JsonObject Terminal(string id)
    {
        var elapsed = Stopwatch.StartNew();
        while (elapsed.Elapsed.TotalSeconds < 40)
        {
            var state = Client.Call("status", new JsonObject { ["execution_id"] = id });
            if (state["state"].Text() is "exited" or "rejected" or "timed_out" or "cancelled" or "unknown" or "tool_error" or "start_failed") return state;
            Thread.Sleep(100);
        }
        throw new Exception("execution did not terminate: " + id);
    }
    internal JsonObject Execute(JsonObject form)
    { var start = Start(form); return Terminal(start["execution_id"].String()); }
    internal string Output(string id, string stream = "stdout") => Client.Call("output", new JsonObject
    { ["execution_id"] = id, ["stream"] = stream, ["count"] = 4096 })["text"].String();
    internal void Restart()
    { Client.Dispose(); Save(PolicyPath, Policy); Client = new(PolicyPath); }
    internal JsonObject Envelope(string id) => Read(Path.Combine(Serve, id, "request.json"));
    internal JsonObject Anchor() => new()
    {
        ["schema_version"] = 2, ["policy"] = new JsonObject { ["path"] = PolicyPath, ["sha256"] = FileHash(PolicyPath) },
        ["runtime_files"] = new JsonArray(PolicyMaintenance.RuntimeNames(Path.GetDirectoryName(TestRunner.Server)!).Select(name =>
        {
            string path = Path.Combine(Path.GetDirectoryName(TestRunner.Server)!, name);
            return (JsonNode?)new JsonObject { ["path"] = path, ["sha256"] = FileHash(path) };
        }).ToArray())
    };
    internal static (int Exit, string Out, string Error) Run(string executable, string[] args, string? input = null)
    {
        using var process = Process.Start(WindowsProcess.StartInfo(executable, args, TestRunner.Root))!;
        var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
        if (input is not null) process.StandardInput.Write(input);
        process.StandardInput.Close();
        Check.True(process.WaitForExit(60000), "child did not exit");
        return (process.ExitCode, stdout.GetAwaiter().GetResult(), stderr.GetAwaiter().GetResult());
    }
    public void Dispose() => Client.Dispose(); // Execution evidence stays on disk.
}
