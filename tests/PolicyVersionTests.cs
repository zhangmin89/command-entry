using System.Text.Json.Nodes;
using CommandEntry;
using static CommandEntry.RecordJson;

namespace CommandEntry.Tests;

[Trait("Suite", "Regression")]
public sealed class PolicyVersionTests
{
    [Theory, Trait("Category", "Unit")]
    [InlineData("1")]
    [InlineData("2")]
    [InlineData("4")]
    [InlineData("null")]
    [InlineData("\"3\"")]
    [InlineData("true")]
    public void ValidatorRejectsUnsupportedOrMalformedVersion(string json)
    {
        var policy = new JsonObject { ["version"] = JsonNode.Parse(json) };
        Assert.Contains(PolicyMaintenance.Validate(policy), problem => problem.Text() == "version must be 3");
    }

    [Theory, Trait("Category", "Integration")]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(4)]
    public void ServerAndOwnerRejectUnsupportedVersionBeforeBusinessExecution(int version)
    {
        using var f = new Fixture();
        Assert.Equal(3, f.Policy.Int("version", 0));
        Assert.Empty(PolicyMaintenance.Validate(f.Policy));
        var completed = f.Execute(f.Form("output", "1"));
        Assert.Equal("exited", completed["state"].String());
        Assert.Equal(0L, completed["process"]!["exit_code"].Integer("exit_code"));

        var policy = f.Policy.Copy().Object();
        policy["version"] = version;
        string candidate = f.FilePath("unsupported-policy.json");
        WriteNew(candidate, policy);
        var server = Fixture.Run(TestEnvironment.Server, ["--policy", candidate]);
        Assert.Equal(125, server.Exit);
        Assert.Contains("policy_version_required", server.Error);

        string request = Path.Combine(f.Serve, completed["execution_id"].String(), "request.json");
        var owner = Fixture.Run(TestEnvironment.Server, ["run", "--request", request, "--policy", candidate]);
        Assert.Equal(125, owner.Exit);
        Assert.Contains("policy_version_required", owner.Error);
        Assert.Equal("once\n", File.ReadAllText(f.FilePath("writes.txt")));
        Assert.Equal(request, Assert.Single(Directory.EnumerateFiles(f.Serve, "request.json", SearchOption.AllDirectories)));
    }
}
