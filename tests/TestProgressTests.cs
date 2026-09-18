using System.Diagnostics;
using System.Reflection;
using CommandEntry;

namespace CommandEntry.Tests;

public sealed class TestProgressTests
{
    [Theory, Trait("Category", "Integration")]
    [InlineData(true)]
    [InlineData(false)]
    public async Task RedirectedRunnerReportsProgressBeforeCompletion(bool useDetailedDotnetTest)
    {
        string[] selected = ["CommandEntry.Tests.LifecycleTests.WaitBudgetAndTerminalResults", "CommandEntry.Tests.LifecycleTests.OwnerSurvivesMcpServerExit"];
        string configuration = typeof(TestProgressTests).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>().Single(item => item.Key == "BuildConfiguration").Value!;
        string resultsDirectory = Path.Combine(TestEnvironment.Root, "artifacts", "test-results", "progress-" + Guid.NewGuid().ToString("N"));
        string[] args = useDetailedDotnetTest
            ? ["test", "--project", Path.Combine(TestEnvironment.Root, "tests", "CommandEntry.Tests.csproj"), "--configuration", configuration, "--no-build", "--output", "Detailed", "--filter-method", .. selected, "--results-directory", resultsDirectory]
            : [typeof(TestProgressTests).Assembly.Location, "--filter-method", .. selected, "--results-directory", resultsDirectory];
        var startInfo = WindowsProcess.StartInfo("dotnet", args, TestEnvironment.Root);
        startInfo.Environment["DOTNET_CLI_UI_LANGUAGE"] = "en-US";
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
                if (firstProgress is null && selected.Any(name => line.TrimStart().StartsWith(progressPrefix + name, StringComparison.Ordinal)) && !process.HasExited) firstProgress = elapsed.Elapsed;
            }
        }
        Task stdout = ReadOutput();
        try
        {
            await process.WaitForExitAsync(TestContext.Current.CancellationToken).WaitAsync(TimeSpan.FromSeconds(60), TestContext.Current.CancellationToken);
            TimeSpan completed = elapsed.Elapsed;
            await stdout;
            Assert.Equal(0, process.ExitCode);
            // Both selected tests take multiple seconds; the first result must precede teardown.
            Assert.True(firstProgress is not null && completed - firstProgress.Value >= TimeSpan.FromSeconds(1), "No live test progress was observed. Output: " + string.Join('\n', lines) + "\n" + await stderr);
            foreach (string name in selected) Assert.Contains(lines, line => line.TrimStart().StartsWith(passedPrefix + name, StringComparison.Ordinal));
        }
        finally
        {
            if (!process.HasExited) { process.Kill(entireProcessTree: true); Assert.True(process.WaitForExit(10000), "Test subprocess did not exit after cancellation"); }
            await stdout; _ = await stderr;
        }
    }
}
