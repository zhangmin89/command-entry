using System.Text.Json.Nodes;
using CommandEntry;
using static CommandEntry.RecordJson;

namespace CommandEntry.Tests;

internal static class PublicationMaintenanceTests
{
    internal static string Install(Fixture f)
    {
        string install = f.FilePath("install"); Directory.CreateDirectory(install);
        foreach (string file in Directory.GetFiles(Path.GetDirectoryName(TestRunner.Server)!))
            if (Path.GetExtension(file) is ".exe" or ".dll" or ".json") File.Copy(file, Path.Combine(install, Path.GetFileName(file)));
        File.Copy(f.PolicyPath, Path.Combine(install, "policy.json"));
        _ = PolicyMaintenance.BuildBinding(install, Path.Combine(install, "policy.json"), Path.Combine(install, "binding.json"));
        foreach (var (id, fingerprint) in PublicationMaintenance.Identities)
        {
            string directory = Path.Combine(install, "serve-input", id); Directory.CreateDirectory(directory);
            WriteNew(Path.Combine(directory, "request.json"), new JsonObject { ["content_fingerprint"] = fingerprint, ["business"] = new JsonObject { ["cwd"] = f.DirectoryPath } });
        }
        return install;
    }

    [Case]
    private static void PreviewPreservesInstallAndRecords()
    {
        using var f = new Fixture(); string install = Install(f); string binding = FileHash(Path.Combine(install, "binding.json"));
        var plan = PublicationMaintenance.Run(install, Path.GetDirectoryName(TestRunner.Server)!, false);
        Check.True(!plan["apply"].IsTrue()); Check.Equal(3, plan["moves"].Array().Count);
        Check.Equal(binding, FileHash(Path.Combine(install, "binding.json"))); Check.True(!Directory.Exists(plan["backup_directory"].String()));
        foreach (var item in plan["moves"].Array()) { Check.True(Directory.Exists(item!["source"].String())); Check.True(!Directory.Exists(item["destination"].String())); }
    }

    [Case]
    private static void ApplyBacksUpAndMovesRecordsIntact()
    {
        using var f = new Fixture(); string install = Install(f); string policy = FileHash(Path.Combine(install, "policy.json"));
        var requests = PublicationMaintenance.Identities.ToDictionary(item => item.Id, item => FileHash(Path.Combine(install, "serve-input", item.Id, "request.json")));
        var result = PublicationMaintenance.Run(install, Path.GetDirectoryName(TestRunner.Server)!, true); Check.Equal("verified", result["state"].String());
        Check.Equal(policy, FileHash(Path.Combine(install, "policy.json"))); var manifest = Read(result["manifest"].String());
        foreach (var item in manifest["moves"].Array())
        {
            string destination = item!["destination"].String(); Check.True(!Directory.Exists(item["source"].String()));
            Check.Equal(requests[Path.GetFileName(destination)], FileHash(Path.Combine(destination, "request.json")));
        }
        Check.Equal(3L, result["quarantined_directories"].Integer("count"));
        Check.Equal(policy, Read(Path.Combine(install, "binding.json"))["policy"]!["sha256"].String());
        Check.True(File.Exists(Path.Combine(manifest["backup_directory"].String(), "CommandEntry.exe")));
    }

    [Case]
    private static void ExistingQuarantineOrNewClaimPreventsMutation()
    {
        foreach (bool claim in new[] { false, true })
        {
            using var f = new Fixture(); string install = Install(f); string hash = FileHash(Path.Combine(install, "binding.json"));
            if (claim)
            {
                string directory = Path.Combine(install, "serve-input", "_claims", PublicationMaintenance.Identities[0].Fingerprint); Directory.CreateDirectory(directory);
                WriteNew(Path.Combine(directory, "claim.json"), new JsonObject { ["execution_id"] = PublicationMaintenance.Identities[0].Id });
            }
            else Directory.CreateDirectory(Path.Combine(install, "quarantine", "half-published-20260914"));
            Check.Throws<InvalidRequest>(() => PublicationMaintenance.Run(install, Path.GetDirectoryName(TestRunner.Server)!, true), claim ? "Execution or claim now exists" : "Maintenance target already exists");
            Check.Equal(hash, FileHash(Path.Combine(install, "binding.json"))); Check.True(!Directory.Exists(Path.Combine(install, "maintenance")));
            foreach (var (id, _) in PublicationMaintenance.Identities) Check.True(File.Exists(Path.Combine(install, "serve-input", id, "request.json")));
        }
    }

    [Case]
    private static void RunningInstalledServerPreventsMutation()
    {
        using var f = new Fixture(); string install = Install(f); string hash = FileHash(Path.Combine(install, "binding.json"));
        using var active = new McpClient(Path.Combine(install, "policy.json"), Path.Combine(install, "binding.json"), Path.Combine(install, "CommandEntry.exe"));
        Check.Throws<InvalidRequest>(() => PublicationMaintenance.Run(install, Path.GetDirectoryName(TestRunner.Server)!, true), "Stop the listed command-entry");
        Check.Equal(hash, FileHash(Path.Combine(install, "binding.json"))); Check.True(!Directory.Exists(Path.Combine(install, "maintenance")));
    }
}
