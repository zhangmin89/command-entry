using System.Text.Json.Nodes;
using CommandEntry;
using static CommandEntry.RecordJson;

namespace CommandEntry.Tests;

public sealed class WaitPolicyTests
{
    [Theory, Trait("Category", "Unit")]
    [InlineData("wait_budget_seconds")]
    [InlineData("wait_poll_interval_seconds")]
    [InlineData("wait_stop_after_no_progress")]
    public void ValidatorRequiresEachWaitSetting(string key)
    {
        var policy = new JsonObject { ["wait_budget_seconds"] = 30, ["wait_poll_interval_seconds"] = 5, ["wait_stop_after_no_progress"] = 12 };
        policy.Remove(key);
        Assert.Contains(PolicyMaintenance.Validate(policy), problem => problem.Text() == key + "_required");
    }

    [Theory, Trait("Category", "Integration")]
    [InlineData("wait_budget_seconds")]
    [InlineData("wait_poll_interval_seconds")]
    [InlineData("wait_stop_after_no_progress")]
    public void ServerRejectsMissingWaitSettingBeforeCreatingServeRoot(string key)
    {
        using var f = new Fixture();
        var policy = f.Policy.Copy().Object(); policy.Remove(key);
        string serve = f.FilePath("must-not-create"), candidate = f.FilePath("missing-wait-policy.json");
        policy["serve_root"] = serve; WriteNew(candidate, policy);
        var validation = Fixture.Run(TestEnvironment.Server, ["validate-policy", "--policy", candidate]);
        var startup = Fixture.Run(TestEnvironment.Server, ["--policy", candidate]);
        Assert.Equal(1, validation.Exit);
        Assert.Contains(JsonNode.Parse(validation.Out)!["problems"].Array(), problem => problem.Text() == key + "_required");
        Assert.Equal(125, startup.Exit);
        Assert.Contains(key + "_required", startup.Error);
        Assert.False(Directory.Exists(serve));
    }

    [Theory, Trait("Category", "Integration")]
    [InlineData("wait_budget_seconds", 1, 300)]
    [InlineData("wait_poll_interval_seconds", 1, 60)]
    [InlineData("wait_stop_after_no_progress", 2, 100)]
    public void ServerRejectsInvalidWaitSettingBeforeCreatingServeRoot(string key, int low, int high)
    {
        using var f = new Fixture();
        string serve = f.FilePath("must-not-create"); int index = 0;
        foreach (JsonNode? value in new JsonNode?[] { null, JsonValue.Create("1"), JsonValue.Create(true), JsonValue.Create(1.5), JsonValue.Create(low - 1), JsonValue.Create(high + 1) })
        {
            var policy = f.Policy.Copy().Object(); policy[key] = value?.Copy(); policy["serve_root"] = serve;
            string candidate = f.FilePath("invalid-wait-policy-" + index++ + ".json"); WriteNew(candidate, policy);
            var startup = Fixture.Run(TestEnvironment.Server, ["--policy", candidate]);
            Assert.Equal(125, startup.Exit);
            Assert.Contains(key + "_out_of_range", startup.Error);
            Assert.False(Directory.Exists(serve));
        }
    }
}
