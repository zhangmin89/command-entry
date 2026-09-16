using System.Text.Json.Nodes;
using static CommandEntry.RecordJson;

namespace CommandEntry.Tests;

public sealed class ProgramDiscoveryTests
{
    private static JsonObject ProgramSchema(Fixture fixture) => fixture.Client.Rpc("tools/list", new())["tools"].Array()
        .Single(tool => tool!["name"].Text() == "start_operation")!["inputSchema"]!["properties"]!["program"].Object();

    private static void Rejected(Fixture fixture, string program, string reason)
    {
        var form = fixture.Form("location"); form["program"] = program;
        var result = fixture.Client.Raw("start_operation", form);
        Assert.True(result["isError"].IsTrue(), result.ToJsonString());
        Assert.Equal(reason, JsonNode.Parse(result["content"]![0]!["text"].String())!["reason"].String());
    }

    [Fact, Trait("Category", "Integration")]
    public void AdvertisesExactConfiguredKeysAndPreservesValidation()
    {
        using var f = new Fixture();
        var programs = f.Policy["programs"].Object();
        programs["curl"] = programs["probe"]!.Copy();
        programs["tar.exe"] = programs["probe"]!.Copy();
        programs["ProbeAlias"] = programs["probe"]!.Copy();
        programs.Remove("server");
        f.Restart();
        var schema = ProgramSchema(f);
        Assert.Equal("string", schema["type"].String());
        JsonAssert.Equal(new JsonArray("ProbeAlias", "curl", "powershell", "probe", "python", "tar.exe"), schema["enum"]);
        JsonAssert.Equal(schema, ProgramSchema(f));
        foreach (string name in new[] { "curl.exe", "tar", "probealias", "server", TestEnvironment.ProbeExe })
            Rejected(f, name, "program_not_configured");
        Assert.Empty(Directory.GetDirectories(f.Serve));
        foreach (string name in new[] { "curl", "tar.exe", "ProbeAlias" })
        {
            var form = f.Form("location"); form["program"] = name;
            var state = f.Execute(form);
            Assert.Equal("exited", state["state"].String());
            Assert.Equal(0L, state["process"]!["exit_code"].Integer("exit"));
            Assert.Equal(f.DirectoryPath, JsonNode.Parse(f.Output(state["execution_id"].String()))!["cwd"].String());
        }
    }

    [Fact, Trait("Category", "Integration")]
    public void DiscoveryUsesLoadedPolicyUntilRestart()
    {
        using var f = new Fixture();
        JsonAssert.Equal(new JsonArray("powershell", "probe", "python", "server"), ProgramSchema(f)["enum"]);
        var programs = f.Policy["programs"].Object();
        programs["new-key"] = programs["probe"]!.Copy();
        programs.Remove("server");
        Save(f.PolicyPath, f.Policy);
        JsonAssert.Equal(new JsonArray("powershell", "probe", "python", "server"), ProgramSchema(f)["enum"]);
        Rejected(f, "new-key", "program_not_configured");
        Rejected(f, "probe", "policy_changed_since_review");
        Assert.Empty(Directory.GetDirectories(f.Serve));
        f.Restart();
        JsonAssert.Equal(new JsonArray("new-key", "powershell", "probe", "python"), ProgramSchema(f)["enum"]);
        Rejected(f, "server", "program_not_configured");
        var form = f.Form("location"); form["program"] = "new-key";
        var state = f.Execute(form);
        Assert.Equal("exited", state["state"].String());
        Assert.Equal(0L, state["process"]!["exit_code"].Integer("exit"));
    }
}
