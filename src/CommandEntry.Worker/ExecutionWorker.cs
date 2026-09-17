using System.Diagnostics;
using System.Text.Json.Nodes;
using static CommandEntry.RecordJson;

namespace CommandEntry;

internal static class ExecutionWorker
{
    internal static async Task<int> Run()
    {
        // The owner's Packed(message) escapes non-ASCII keys and values, so this
        // handshake is independent of the console input code page.
        var message = JsonNode.Parse(await Console.In.ReadLineAsync() ?? "").Object();
        Require(message["handshake"].Text() == "job_assigned", "job_handshake_required");
        string[] argv = message["argv"].Array().Select(a => a.String()).ToArray();
        Require(argv.Length > 0, "worker_argv_required");
        var info = WindowsProcess.StartInfo(argv[0], argv.Skip(1), message["cwd"].String());
        if (message["powershell_request"] is { } invocation) info.Environment[PowerShellAdapter.RequestVariable] = invocation.String();
        info.RedirectStandardOutput = false; info.RedirectStandardError = false;
        using var input = message["stdin_file"] is null ? null : File.OpenRead(message["stdin_file"].String());
        using var child = Process.Start(info)!;
        PublishBusinessProcess(message["record_dir"].String(), WindowsProcess.Observe(child.Id));
        async Task FeedInput()
        {
            try { if (input is not null) await input.CopyToAsync(child.StandardInput.BaseStream); }
            catch (IOException) { /* A business process may close stdin before consuming the file. */ }
            finally { child.StandardInput.Close(); }
        }
        var feed = FeedInput();
        await child.WaitForExitAsync();
        child.StandardInput.Close();
        await feed;
        return child.ExitCode;
    }

    internal static void PublishBusinessProcess(string directory, JsonObject observation) =>
        PublishNew(Path.Combine(directory, "business-process.json"), observation);
}
