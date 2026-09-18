using System.Diagnostics;
using System.Reflection;
using System.Text.RegularExpressions;
using CommandEntry;

namespace CommandEntry.Tests;

public sealed class TestProgressTests
{
    [Theory, Trait("Category", "Integration")]
    [InlineData(true, false)]
    [InlineData(true, true)]
    [InlineData(false, false)]
    [InlineData(false, true)]
    public async Task RedirectedRunnerReportsProgressBeforeCompletion(bool useDetailedDotnetTest, bool useAnsiColor)
    {
        string[] selected = ["CommandEntry.Tests.LifecycleTests.WaitBudgetAndTerminalResults", "CommandEntry.Tests.LifecycleTests.OwnerSurvivesMcpServerExit"];
        string configuration = typeof(TestProgressTests).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>().Single(item => item.Key == "BuildConfiguration").Value!;
        string resultsDirectory = Path.Combine(TestEnvironment.Root, "artifacts", "test-results", "progress-" + Guid.NewGuid().ToString("N"));
        string[] args = useDetailedDotnetTest
            ? ["test", "--project", Path.Combine(TestEnvironment.Root, "tests", "CommandEntry.Tests.csproj"), "--configuration", configuration, "--no-build", "--output", "Detailed", "--filter-method", .. selected, "--results-directory", resultsDirectory]
            : [typeof(TestProgressTests).Assembly.Location, "--filter-method", .. selected, "--results-directory", resultsDirectory];
        var startInfo = WindowsProcess.StartInfo("dotnet", args, TestEnvironment.Root);
        startInfo.Environment["DOTNET_CLI_UI_LANGUAGE"] = "en-US";
        // The SDK selects simple ANSI rendering in CI, unless Codex detection disables it.
        startInfo.Environment["GITHUB_ACTIONS"] = useAnsiColor ? "true" : "false";
        startInfo.Environment["TF_BUILD"] = "false";
        startInfo.Environment.Remove("CODEX_CLI");
        startInfo.Environment.Remove("CODEX_SANDBOX");
        using var process = Process.Start(startInfo)!;
        process.StandardInput.Close();
        var stderr = process.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        var lines = new List<string>(); TimeSpan? firstProgress = null; var elapsed = Stopwatch.StartNew();
        string progressPrefix = useDetailedDotnetTest ? "passed " : "[test-progress] Running: ";
        string passedPrefix = useDetailedDotnetTest ? "passed " : "[test-progress] Passed: ";
        async Task ReadOutput()
        {
            while (await process.StandardOutput.ReadLineAsync(TestContext.Current.CancellationToken) is { } line)
            {
                lines.Add(line);
                if (firstProgress is null && selected.Any(name => IsTestEvent(line, progressPrefix, name)) && !process.HasExited) firstProgress = elapsed.Elapsed;
            }
        }
        Task stdout = ReadOutput();
        try
        {
            await process.WaitForExitAsync(TestContext.Current.CancellationToken).WaitAsync(TimeSpan.FromSeconds(60), TestContext.Current.CancellationToken);
            TimeSpan completed = elapsed.Elapsed;
            await stdout;
            Assert.Equal(0, process.ExitCode);
            if (useDetailedDotnetTest) Assert.Equal(useAnsiColor, lines.Any(line => line.Contains("\u001b[", StringComparison.Ordinal)));
            // Both selected tests take multiple seconds; the first result must precede teardown.
            Assert.True(firstProgress is not null && completed - firstProgress.Value >= TimeSpan.FromSeconds(1), "No live test progress was observed. Output: " + string.Join('\n', lines) + "\n" + await stderr);
            foreach (string name in selected) Assert.Contains(lines, line => IsTestEvent(line, passedPrefix, name));
        }
        finally
        {
            if (!process.HasExited) { process.Kill(entireProcessTree: true); Assert.True(process.WaitForExit(10000), "Test subprocess did not exit after cancellation"); }
            await stdout; _ = await stderr;
        }
    }

    // Keep captured lines intact for diagnostics; ignore only SGR color/style sequences when matching.
    private static bool IsTestEvent(string line, string prefix, string name) =>
        Regex.Replace(line, @"\x1b\[[0-9;]*m", string.Empty).TrimStart().StartsWith(prefix + name, StringComparison.Ordinal);
}
