using System.Reflection;
using System.Text.Json.Nodes;
using CommandEntry;
using static CommandEntry.RecordJson;

namespace CommandEntry.Tests;

internal static class TestEnvironment
{
    private static string Metadata(string key) => typeof(TestEnvironment).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>().Single(item => item.Key == key).Value!;
    internal static string Root => Metadata("RepositoryRoot");
    private static string Configuration => Metadata("BuildConfiguration");
    internal static string Server => Environment.GetEnvironmentVariable("COMMAND_ENTRY_TEST_SERVER")
        ?? Path.Combine(Root, "src", "CommandEntry", "bin", Configuration, "net10.0-windows", "win-x64", "CommandEntry.exe");
    internal static string ProbeExe => Path.Combine(Root, "tests", "CommandEntry.TestProbe", "bin", Configuration, "net10.0-windows", "win-x64", "CommandEntry.TestProbe.exe");

    internal static JsonObject TemplatePolicy()
    {
        var policy = Read(Path.Combine(Root, "policy.json"));
        foreach (var (key, executable) in new[] { ("powershell", "pwsh.exe"), ("node", "node.exe"), ("python", "python.exe") })
        {
            string? path = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
                .Select(directory => Path.Combine(directory.Trim('"'), executable)).FirstOrDefault(File.Exists);
            Assert.True(path is not null, "Test interpreter is missing from PATH: " + executable);
            policy["programs"]![key]!["path"] = path;
        }
        return policy;
    }
}
