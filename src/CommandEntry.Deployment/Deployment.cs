using System.Text.Json.Nodes;
using static CommandEntry.RecordJson;

namespace CommandEntry;

internal static class Deployment
{
    internal static JsonObject Prepare(string runtimeRoot, string policyPath, string outputPath)
    {
        string policy = BusinessPaths.Resolve(policyPath, "file");
        using var locks = new FileBindings();
        locks.Add(policy);
        JsonArray problems = PolicyValidator.Validate(Read(policy));
        if (problems.Count > 0) return new() { ["valid"] = false, ["problems"] = problems };
        var result = BindingBuilder.BuildBinding(runtimeRoot, policy, outputPath);
        result["valid"] = true;
        return result;
    }
}
