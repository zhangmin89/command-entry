using System.Text.Json.Nodes;
using CommandEntry;
using static CommandEntry.RecordJson;

namespace CommandEntry.Tests;

[Trait("Suite", "Smoke")]
public sealed class SmokeTests
{
    [Fact, Trait("Category", "Integration")]
    public void EndToEndSessionClosesCleanly()
    {
        using var f = new Fixture();
        var initialized = f.Client.Initialization;
        Assert.Equal("2025-06-18", initialized["protocolVersion"].String());
        Assert.Equal("command-entry-exec-server", initialized["serverInfo"]!["name"].String());
        Assert.Equal("pure-beta.server.3-csharp", initialized["serverInfo"]!["version"].String());
        Assert.True(initialized["capabilities"]!["tools"] is JsonObject);
        var tools = f.Client.Rpc("tools/list", new())["tools"].Array();
        Assert.Equal("cancel,output,read_text,start_operation,status,wait", string.Join(',', tools.Select(tool => tool!["name"].String()).Order()));

        string text = f.Write("hello.txt", "smoke-line-1\n");
        Assert.Equal("smoke-line-1\n", f.Client.Call("read_text", new JsonObject { ["file"] = text })["text"].String());
        string script = f.Write("say.ps1", "param()\nSet-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\nWrite-Output 'business-stdout-ok'\n");
        var form = f.Script(script);
        var first = f.Start(form); string id = first["execution_id"].String();
        Assert.Equal("exited", f.Terminal(id)["state"].String());
        var waited = f.Client.Call("wait", new JsonObject { ["execution_id"] = id });
        Assert.Equal("terminal", waited["wait_outcome"].String());
        Assert.Equal("exited", waited["state"].String());
        Assert.Equal("business-stdout-ok\n", f.Output(id));
        var status = f.Client.Call("status", new JsonObject { ["execution_id"] = id });
        Assert.Equal(id, status["execution_id"].String());
        Assert.Equal("exited", status["state"].String());
        Assert.Equal(0L, status["process"]!["exit_code"].Integer("exit"));
        Assert.True(status["operation_result"]!["acceptable_exit"].IsTrue());

        // The old smoke script repeats the request after completion: this is a new intent.
        var repeated = f.Execute(form); string nextId = repeated["execution_id"].String();
        Assert.True(nextId != id);
        Assert.Equal("exited", repeated["state"].String());
        Assert.Equal(0L, repeated["process"]!["exit_code"].Integer("exit"));
        Assert.Equal("business-stdout-ok\n", f.Output(nextId));

        var closed = f.Client.CloseInput();
        Assert.Equal(0, closed.Exit); Assert.Equal("", closed.Error);
        var events = File.ReadLines(f.FilePath("logs/server-events.jsonl")).Select(line => JsonNode.Parse(line).Object()).ToArray();
        foreach (string kind in new[] { "startup", "read_text", "start_operation", "wait", "output", "status" })
            Assert.True(events.Any(item => item["kind"].Text() == kind), "Missing smoke event: " + kind);
        Assert.Equal(2, events.Count(item => item["kind"].Text() == "start_operation"));
        Assert.True(events.Where(item => item["kind"].Text() == "start_operation").All(item => !item["dedup"].IsTrue()));
    }

    [Fact, Trait("Category", "Integration")]
    public void UnknownStartFieldIsRejectedBeforePublication()
    {
        using var f = new Fixture();
        string script = f.Write("must-not-run.ps1", "param()\nSet-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n[IO.File]::WriteAllText('unexpected.txt', 'executed')\n");
        var form = f.Script(script); form["bogus_field"] = "x";
        var rejected = f.Client.Raw("start_operation", form);
        Assert.True(rejected["isError"].IsTrue());
        var error = JsonNode.Parse(rejected["content"]![0]!["text"].String()).Object();
        Assert.Equal("Invalid", error["error"].String());
        Assert.Equal("unknown_form_fields", error["reason"].String());
        Assert.Empty(Directory.GetFileSystemEntries(f.Serve));
        Assert.False(File.Exists(f.FilePath("unexpected.txt")));
        var events = File.ReadLines(f.FilePath("logs/server-events.jsonl")).Select(line => JsonNode.Parse(line).Object()).ToArray();
        Assert.Contains(events, item => item["kind"].Text() == "rejected" && item["tool"].Text() == "start_operation" && item["reason"].Text() == "unknown_form_fields");
    }

    [Fact, Trait("Category", "Integration")]
    public void MissingExecutionStatusIsRejectedAndSessionRemainsUsable()
    {
        using var f = new Fixture();
        const string id = "00000000-0000-4000-8000-000000000000";
        var rejected = f.Client.Raw("status", new JsonObject { ["execution_id"] = id });
        Assert.True(rejected["isError"].IsTrue());
        var error = JsonNode.Parse(rejected["content"]![0]!["text"].String()).Object();
        Assert.Equal("Invalid", error["error"].String());
        Assert.Equal("execution_not_found", error["reason"].String());
        Assert.Empty(Directory.GetFileSystemEntries(f.Serve));
        Assert.False(Directory.Exists(Path.Combine(f.DirectoryPath, ".codex-command-records", id)));
        string text = f.Write("after-error.txt", "session-still-usable\n");
        Assert.Equal("session-still-usable\n", f.Client.Call("read_text", new JsonObject { ["file"] = text })["text"].String());
    }
}
