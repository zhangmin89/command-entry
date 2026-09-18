using System.Text.Json.Nodes;
using static CommandEntry.RecordJson;

namespace CommandEntry;

internal static class PolicyMaintenance
{
    internal static JsonObject Update(string repoRoot, string? policyPath, string? addProgram, string? programPath, string kind = "native")
    {
        string root = BusinessPaths.Resolve(repoRoot, "directory");
        Require(File.Exists(Path.Combine(root, "CommandEntry.exe")), "RepoRoot does not contain CommandEntry.exe.");
        string live = BusinessPaths.Resolve(Path.Combine(root, "policy.json"), "file"), binding = Path.Combine(root, "binding.json");
        string stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N")[..6];
        byte[] candidate;
        if (addProgram is not null)
        {
            Require(programPath is not null, "--program-path is required with --add-program.");
            string program = BusinessPaths.Resolve(programPath!, "file");
            Require(kind is "native" or "python" or "powershell" or "javascript", "unsupported_program_kind");
            var definition = Read(live);
            definition["programs"].Object()[addProgram] = new JsonObject { ["kind"] = kind, ["path"] = program };
            candidate = Packed(definition);
        }
        else candidate = File.ReadAllBytes(policyPath is null ? live : BusinessPaths.Resolve(policyPath, "file"));
        JsonArray problems = PolicyValidator.Validate(JsonNode.Parse(Utf8.GetString(candidate).TrimStart('\ufeff')).Object());
        Require(problems.Count == 0, "Candidate validation failed; nothing was deployed: " + Utf8.GetString(Packed(problems)));
        string backup = Path.Combine(root, "policy-backups", stamp);
        Directory.CreateDirectory(backup);
        File.Copy(live, Path.Combine(backup, "policy.json"), overwrite: false);
        bool hadBinding = File.Exists(binding);
        if (hadBinding) File.Copy(binding, Path.Combine(backup, "binding.json"), overwrite: false);
        string nextBinding = Path.Combine(root, "binding-candidate-" + stamp + ".json");
        try
        {
            if (!File.ReadAllBytes(live).AsSpan().SequenceEqual(candidate)) File.WriteAllBytes(live, candidate);
            _ = BindingBuilder.BuildBinding(root, live, nextBinding);
            File.Move(nextBinding, binding, overwrite: true);
        }
        catch (Exception error) when (ExecutionRecords.Handled(error))
        {
            File.Copy(Path.Combine(backup, "policy.json"), live, overwrite: true);
            if (hadBinding) File.Copy(Path.Combine(backup, "binding.json"), binding, overwrite: true);
            throw new IOException("Mid-flight failure; the old policy+binding pair was restored from " + backup, error);
        }
        return new() { ["state"] = "verified", ["backup"] = backup, ["binding"] = binding,
            ["policy_sha256"] = FileHash(live), ["note"] = "Restart the exec server for the new policy to take effect." };
    }
}
