using System.Reflection.PortableExecutable;
using System.Text.Json.Nodes;
using static CommandEntry.RecordJson;

namespace CommandEntry;

internal static class RuntimeCommands
{
    internal static JsonObject InspectAot(string executable)
    {
        string path = BusinessPaths.Resolve(executable, "file");
        using var stream = File.OpenRead(path);
        using var image = new PEReader(stream);
        Require(image.PEHeaders.CoffHeader.Machine == Machine.Amd64, "The published executable is not x64.");
        Require(image.PEHeaders.PEHeader?.Magic == PEMagic.PE32Plus, "Expected a PE32+ optional header.");
        Require(image.PEHeaders.CorHeader is null && image.PEHeaders.PEHeader?.CorHeaderTableDirectory.Size == 0,
            "A managed CLR image was published instead of native code.");
        string root = Path.GetDirectoryName(path)!;
        foreach (string name in new[] { "CommandEntry.dll", "CommandEntry.runtimeconfig.json" })
            Require(!File.Exists(Path.Combine(root, name)), "Unexpected managed application companion: " + name);
        foreach (string name in PolicyMaintenance.RuntimeNames(root))
            Require(File.Exists(Path.Combine(root, name)), "Runtime file missing: " + name);
        return new() { ["executable"] = path, ["architecture"] = "x64", ["native_aot"] = true, ["bytes"] = stream.Length };
    }

    internal static Dictionary<string, string> Options(string[] args, params string[] allowed)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        Require(args.Length % 2 == 0, "expected_named_option_value_pairs");
        for (int i = 0; i < args.Length; i += 2)
        {
            Require(allowed.Contains(args[i]) && !values.ContainsKey(args[i]), "unknown_or_duplicate_option: " + args[i]);
            values.Add(args[i], args[i + 1]);
        }
        return values;
    }

    internal static string Required(this Dictionary<string, string> options, string name) =>
        options.TryGetValue(name, out string? value) && value.Length > 0 ? value : throw new InvalidRequest(name + "_required");

    internal static async Task<int?> Run(string[] args)
    {
        if (args.Length == 0) return null;
        JsonObject result;
        int exit = 0;
        switch (args[0])
        {
            case "sentinel":
                var sentinel = Options(args[1..], "--records");
                result = Sentinel.Run(await Console.In.ReadToEndAsync(), sentinel.GetValueOrDefault("--records", Path.Combine(AppContext.BaseDirectory, "hook-records")));
                break;
            case "validate-policy":
                var validation = Options(args[1..], "--policy");
                var policy = Read(BusinessPaths.Resolve(validation.Required("--policy"), "file"));
                JsonArray problems = PolicyMaintenance.Validate(policy);
                result = new() { ["valid"] = problems.Count == 0, ["problems"] = problems,
                    ["programs"] = new JsonArray((policy["programs"] as JsonObject ?? new()).Select(pair => pair.Key).Order().Select(name => (JsonNode?)JsonValue.Create(name)).ToArray()),
                    ["working_roots"] = policy["working_roots"]?.Copy() };
                exit = problems.Count == 0 ? 0 : 1;
                break;
            case "build-binding":
                var build = Options(args[1..], "--runtime-root", "--policy", "--output");
                result = PolicyMaintenance.BuildBinding(build.Required("--runtime-root"), build.Required("--policy"), build.Required("--output"));
                break;
            case "update-policy":
                var update = Options(args[1..], "--repo-root", "--policy", "--add-program", "--program-path", "--kind");
                result = PolicyMaintenance.Update(update.Required("--repo-root"), update.GetValueOrDefault("--policy"),
                    update.GetValueOrDefault("--add-program"), update.GetValueOrDefault("--program-path"), update.GetValueOrDefault("--kind", "native"));
                break;
            case "metrics":
                var metrics = Options(args[1..], "--records", "--events", "--serve");
                result = Metrics.Collect(metrics.Required("--records"), metrics.Required("--events"), metrics.Required("--serve"));
                break;
            case "inspect-aot":
                var aot = Options(args[1..], "--executable");
                result = InspectAot(aot.Required("--executable"));
                break;
            case "publication-maintenance":
                var publication = Options(args[1..], "--install-root", "--source-root", "--apply");
                string apply = publication.GetValueOrDefault("--apply", "false");
                Require(apply is "true" or "false", "--apply_must_be_true_or_false");
                result = PublicationMaintenance.Run(publication.Required("--install-root"), publication.Required("--source-root"), apply == "true");
                break;
            default: return null;
        }
        Console.WriteLine(Utf8.GetString(Packed(result)));
        return exit;
    }
}
