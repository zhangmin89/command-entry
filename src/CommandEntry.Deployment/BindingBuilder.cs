using System.Text.Json.Nodes;
using static CommandEntry.RecordJson;

namespace CommandEntry;

internal static class BindingBuilder
{
    internal static string[] RuntimeNames(string root) => RuntimeNames(File.Exists(Path.Combine(root, "CommandEntry.dll")));

    internal static string[] RuntimeNames(bool managed) => managed
        ? ["CommandEntry.exe", "CommandEntry.dll", "CommandEntry.deps.json", "CommandEntry.runtimeconfig.json",
            "CommandEntry.Common.dll", "CommandEntry.Server.dll", "CommandEntry.Owner.dll", "CommandEntry.Worker.dll", "CommandEntry.Deployment.dll"]
        : ["CommandEntry.exe"];

    internal static JsonObject BuildBinding(string runtimeRoot, string policyPath, string outputPath)
    {
        string root = BusinessPaths.Resolve(runtimeRoot, "directory"), policy = BusinessPaths.Resolve(policyPath, "file");
        string output = RequestShape.Absolute(JsonValue.Create(outputPath));
        Require(!File.Exists(output) && !Directory.Exists(output), "Refusing to overwrite an existing binding: " + output);
        Require(Directory.Exists(Path.GetDirectoryName(output)), "The output parent directory must already exist.");
        using var locks = new FileBindings();
        locks.Add(policy);
        var runtime = new JsonArray();
        foreach (string name in RuntimeNames(root))
        {
            string path = BusinessPaths.Resolve(Path.Combine(root, name), "file"); locks.Add(path);
            runtime.Add((JsonNode)new JsonObject { ["path"] = path, ["sha256"] = locks.Bindings[path]?.Copy() });
        }
        var binding = new JsonObject
        {
            ["schema_version"] = 2, ["phase"] = File.Exists(Path.Combine(root, "CommandEntry.dll")) ? "csharp_managed" : "csharp_native_aot",
            ["policy"] = new JsonObject { ["path"] = policy, ["sha256"] = locks.Bindings[policy]?.Copy() }, ["runtime_files"] = runtime
        };
        WriteNew(output, binding);
        Require(JsonNode.DeepEquals(Read(output), binding), "Written binding did not pass artifact validation.");
        return new() { ["written"] = output, ["files"] = runtime.Count, ["policy_sha256"] = locks.Bindings[policy]?.Copy() };
    }
}
