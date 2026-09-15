using System.Text.Json.Nodes;
using CommandEntry;
using static CommandEntry.RecordJson;

namespace CommandEntry.Tests;

internal static class SmokeTests
{
    [Case]
    private static void EndToEndSessionClosesCleanly()
    {
        using var f = new Fixture();
        var initialized = f.Client.Initialization;
        Check.Equal("2025-06-18", initialized["protocolVersion"].String());
        Check.Equal("command-entry-exec-server", initialized["serverInfo"]!["name"].String());
        Check.Equal("pure-beta.server.3-csharp", initialized["serverInfo"]!["version"].String());
        Check.True(initialized["capabilities"]!["tools"] is JsonObject);
        var tools = f.Client.Rpc("tools/list", new())["tools"].Array();
        Check.Equal("cancel,output,read_text,start_operation,status,wait", string.Join(',', tools.Select(tool => tool!["name"].String()).Order()));

        string text = f.Write("hello.txt", "smoke-line-1\n");
        Check.Equal("smoke-line-1\n", f.Client.Call("read_text", new JsonObject { ["file"] = text })["text"].String());
        string script = f.Write("say.ps1", "param()\nSet-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\nWrite-Output 'business-stdout-ok'\n");
        var form = f.Script(script);
        var first = f.Start(form); string id = first["execution_id"].String();
        Check.Equal("exited", f.Terminal(id)["state"].String());
        var waited = f.Client.Call("wait", new JsonObject { ["execution_id"] = id });
        Check.Equal("terminal", waited["wait_outcome"].String());
        Check.Equal("exited", waited["state"].String());
        Check.Equal("business-stdout-ok\n", f.Output(id));
        var status = f.Client.Call("status", new JsonObject { ["execution_id"] = id });
        Check.Equal(id, status["execution_id"].String());
        Check.Equal("exited", status["state"].String());
        Check.Equal(0L, status["process"]!["exit_code"].Integer("exit"));
        Check.True(status["operation_result"]!["acceptable_exit"].IsTrue());

        // The old smoke script repeats the request after completion: this is a new intent.
        var repeated = f.Execute(form); string nextId = repeated["execution_id"].String();
        Check.True(nextId != id);
        Check.Equal("exited", repeated["state"].String());
        Check.Equal(0L, repeated["process"]!["exit_code"].Integer("exit"));
        Check.Equal("business-stdout-ok\n", f.Output(nextId));

        var closed = f.Client.CloseInput();
        Check.Equal(0, closed.Exit); Check.Equal("", closed.Error);
        var events = File.ReadLines(f.FilePath("logs/server-events.jsonl")).Select(line => JsonNode.Parse(line).Object()).ToArray();
        foreach (string kind in new[] { "startup", "read_text", "start_operation", "wait", "output", "status" })
            Check.True(events.Any(item => item["kind"].Text() == kind), "Missing smoke event: " + kind);
        Check.Equal(2, events.Count(item => item["kind"].Text() == "start_operation"));
        Check.True(events.Where(item => item["kind"].Text() == "start_operation").All(item => !item["dedup"].IsTrue()));
    }

    [Case]
    private static void UnknownStartFieldIsRejectedBeforePublication()
    {
        using var f = new Fixture();
        string script = f.Write("must-not-run.ps1", "param()\nSet-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n[IO.File]::WriteAllText('unexpected.txt', 'executed')\n");
        var form = f.Script(script); form["bogus_field"] = "x";
        var rejected = f.Client.Raw("start_operation", form);
        Check.True(rejected["isError"].IsTrue());
        var error = JsonNode.Parse(rejected["content"]![0]!["text"].String()).Object();
        Check.Equal("Invalid", error["error"].String());
        Check.Equal("unknown_form_fields", error["reason"].String());
        Check.Equal(0, Directory.GetFileSystemEntries(f.Serve).Length);
        Check.True(!File.Exists(f.FilePath("unexpected.txt")));
        var events = File.ReadLines(f.FilePath("logs/server-events.jsonl")).Select(line => JsonNode.Parse(line).Object()).ToArray();
        Check.True(events.Any(item => item["kind"].Text() == "rejected" && item["tool"].Text() == "start_operation" && item["reason"].Text() == "unknown_form_fields"));
    }

    [Case]
    private static void MissingExecutionStatusIsRejectedAndSessionRemainsUsable()
    {
        using var f = new Fixture();
        const string id = "00000000-0000-4000-8000-000000000000";
        var rejected = f.Client.Raw("status", new JsonObject { ["execution_id"] = id });
        Check.True(rejected["isError"].IsTrue());
        var error = JsonNode.Parse(rejected["content"]![0]!["text"].String()).Object();
        Check.Equal("Invalid", error["error"].String());
        Check.Equal("execution_not_found", error["reason"].String());
        Check.Equal(0, Directory.GetFileSystemEntries(f.Serve).Length);
        Check.True(!Directory.Exists(Path.Combine(f.DirectoryPath, ".codex-command-records", id)));
        string text = f.Write("after-error.txt", "session-still-usable\n");
        Check.Equal("session-still-usable\n", f.Client.Call("read_text", new JsonObject { ["file"] = text })["text"].String());
    }
}
