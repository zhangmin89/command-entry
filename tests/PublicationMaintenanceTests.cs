using System.Text.Json.Nodes;
using CommandEntry;
using static CommandEntry.RecordJson;

namespace CommandEntry.Tests;

public sealed class PublicationMaintenanceTests
{
    internal static string Install(Fixture f)
    {
        string install = f.FilePath("install"); Directory.CreateDirectory(install);
        foreach (string file in Directory.GetFiles(Path.GetDirectoryName(TestEnvironment.Server)!))
            if (Path.GetExtension(file) is ".exe" or ".dll" or ".json") File.Copy(file, Path.Combine(install, Path.GetFileName(file)));
        File.Copy(f.PolicyPath, Path.Combine(install, "policy.json"));
        _ = BindingBuilder.BuildBinding(install, Path.Combine(install, "policy.json"), Path.Combine(install, "binding.json"));
        foreach (var (id, fingerprint) in PublicationMaintenance.Identities)
        {
            string directory = Path.Combine(install, "serve-input", id); Directory.CreateDirectory(directory);
            WriteNew(Path.Combine(directory, "request.json"), new JsonObject { ["content_fingerprint"] = fingerprint, ["business"] = new JsonObject { ["cwd"] = f.DirectoryPath } });
        }
        return install;
    }

    [Fact, Trait("Category", "Integration")]
    public void PreviewPreservesInstallAndRecords()
    {
        using var f = new Fixture(); string install = Install(f); string binding = FileHash(Path.Combine(install, "binding.json"));
        var plan = PublicationMaintenance.Run(install, Path.GetDirectoryName(TestEnvironment.Server)!, false);
        Assert.False(plan["apply"].IsTrue()); Assert.Equal(3, plan["moves"].Array().Count);
        Assert.Equal(binding, FileHash(Path.Combine(install, "binding.json"))); Assert.False(Directory.Exists(plan["backup_directory"].String()));
        foreach (var item in plan["moves"].Array()) { Assert.True(Directory.Exists(item!["source"].String())); Assert.False(Directory.Exists(item["destination"].String())); }
    }

    [Fact, Trait("Category", "Integration")]
    public void ApplyBacksUpAndMovesRecordsIntact()
    {
        using var f = new Fixture(); string install = Install(f); string policy = FileHash(Path.Combine(install, "policy.json"));
        var requests = PublicationMaintenance.Identities.ToDictionary(item => item.Id, item => FileHash(Path.Combine(install, "serve-input", item.Id, "request.json")));
        var result = PublicationMaintenance.Run(install, Path.GetDirectoryName(TestEnvironment.Server)!, true); Assert.Equal("verified", result["state"].String());
        Assert.Equal(policy, FileHash(Path.Combine(install, "policy.json"))); var manifest = Read(result["manifest"].String());
        foreach (var item in manifest["moves"].Array())
        {
            string destination = item!["destination"].String(); Assert.False(Directory.Exists(item["source"].String()));
            Assert.Equal(requests[Path.GetFileName(destination)], FileHash(Path.Combine(destination, "request.json")));
        }
        Assert.Equal(3L, result["quarantined_directories"].Integer("count"));
        Assert.Equal(policy, Read(Path.Combine(install, "binding.json"))["policy"]!["sha256"].String());
        Assert.True(File.Exists(Path.Combine(manifest["backup_directory"].String(), "CommandEntry.exe")));
    }

    [Fact, Trait("Category", "Integration")]
    public void ExistingQuarantineOrNewClaimPreventsMutation()
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
            TestAssert.Throws<InvalidRequest>(() => PublicationMaintenance.Run(install, Path.GetDirectoryName(TestEnvironment.Server)!, true), claim ? "Execution or claim now exists" : "Maintenance target already exists");
            Assert.Equal(hash, FileHash(Path.Combine(install, "binding.json"))); Assert.False(Directory.Exists(Path.Combine(install, "maintenance")));
            foreach (var (id, _) in PublicationMaintenance.Identities) Assert.True(File.Exists(Path.Combine(install, "serve-input", id, "request.json")));
        }
    }

    [Fact, Trait("Category", "Integration")]
    public void RunningInstalledServerPreventsMutation()
    {
        using var f = new Fixture(); string install = Install(f); string hash = FileHash(Path.Combine(install, "binding.json"));
        using var active = new McpClient(Path.Combine(install, "policy.json"), Path.Combine(install, "binding.json"), Path.Combine(install, "CommandEntry.exe"));
        TestAssert.Throws<InvalidRequest>(() => PublicationMaintenance.Run(install, Path.GetDirectoryName(TestEnvironment.Server)!, true), "Stop the listed command-entry");
        Assert.Equal(hash, FileHash(Path.Combine(install, "binding.json"))); Assert.False(Directory.Exists(Path.Combine(install, "maintenance")));
    }
}
