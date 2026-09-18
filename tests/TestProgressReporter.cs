using System.Text;
using Microsoft.Testing.Platform.Builder;
using Microsoft.Testing.Platform.Extensions;
using Microsoft.Testing.Platform.Extensions.Messages;

namespace CommandEntry.Tests;

internal sealed class TestProgressReporter(TextWriter output) : IDataConsumer, IDisposable
{
    public string Uid => "CommandEntry.Tests.Progress";
    public string Version => "1.0.0";
    public string DisplayName => "Command entry test progress";
    public string Description => "Reports actual test transitions to redirected standard output.";
    public Type[] DataTypesConsumed => [typeof(TestNodeUpdateMessage)];
    public Task<bool> IsEnabledAsync() => Task.FromResult(true);

    public Task ConsumeAsync(IDataProducer dataProducer, IData value, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var message = (TestNodeUpdateMessage)value;
        string? state = message.TestNode.Properties.OfType<TestNodeStateProperty>().SingleOrDefault() switch
        {
            InProgressTestNodeStateProperty => "Running",
            PassedTestNodeStateProperty => "Passed",
            FailedTestNodeStateProperty => "Failed",
            ErrorTestNodeStateProperty => "Error",
            TimeoutTestNodeStateProperty => "Timeout",
            SkippedTestNodeStateProperty => "Skipped",
            _ => null
        };
        if (state is not null)
        {
            output.WriteLine($"[test-progress] {state}: {message.TestNode.DisplayName}");
            output.Flush();
        }
        return Task.CompletedTask;
    }

    public void Dispose() => output.Dispose();
}

public static class TestProgressBuilderHook
{
    public static void AddExtensions(ITestApplicationBuilder builder, string[] args)
    {
        // Raw stdout provides live progress for direct assembly execution.
        // dotnet test buffers this channel; use --output Detailed for its platform-event rendering.
        builder.TestHost.AddDataConsumer(_ => new TestProgressReporter(new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false), leaveOpen: true)));
    }
}
