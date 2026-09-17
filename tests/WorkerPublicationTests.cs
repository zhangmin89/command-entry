using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using CommandEntry;
using static CommandEntry.RecordJson;

namespace CommandEntry.Tests;

[Trait("Suite", "Regression")]
public sealed class WorkerPublicationTests
{
    [Fact, Trait("Category", "Integration")]
    public async Task ObservationCannotReadBusinessIdentityUntilPublicationCompletes()
    {
        using var f = new Fixture();
        using var entered = new ManualResetEventSlim(); using var release = new ManualResetEventSlim();
        var cancellation = TestContext.Current.CancellationToken;
        var options = new JsonSerializerOptions { TypeInfoResolver = new DefaultJsonTypeInfoResolver() };
        options.Converters.Add(new PausedNumberConverter());
        var metadata = (JsonTypeInfo<PausedNumber>)options.GetTypeInfo(typeof(PausedNumber));
        var birth = WindowsProcess.Observe(Environment.ProcessId);
        birth["pid"] = JsonValue.Create(new PausedNumber(Environment.ProcessId, entered, release, cancellation), metadata);
        string path = f.FilePath("business-process.json");
        var state = new JsonObject { ["execution_id"] = Guid.NewGuid().ToString(), ["state"] = "running" };
        var writer = Task.Run(() => ExecutionWorker.PublishBusinessProcess(f.DirectoryPath, birth), cancellation);
        try
        {
            Assert.True(entered.Wait(TimeSpan.FromSeconds(10), cancellation), "Writer did not enter serialization.");
            var during = ExecutionRecords.Collect(f.DirectoryPath, state);
            Assert.Null(during["business_observation"]!["alive"]);
            Assert.Null(during["business_observation"]!["same_instance"]);
            Assert.False(File.Exists(path));
        }
        finally { release.Set(); await writer.WaitAsync(TimeSpan.FromSeconds(10), cancellation); }
        Assert.Equal(Environment.ProcessId, Read(path).Int("pid", 0));
        var after = ExecutionRecords.Collect(f.DirectoryPath, state);
        Assert.True(after["business_observation"]!["alive"].IsTrue());
        Assert.True(after["business_observation"]!["same_instance"].IsTrue());
        Assert.Empty(Directory.GetFiles(f.DirectoryPath, "business-process.json.*.pending"));
    }

    [Fact, Trait("Category", "Integration")]
    public void ExistingBusinessIdentityCannotBeOverwritten()
    {
        using var f = new Fixture(); string path = f.FilePath("business-process.json");
        var original = WindowsProcess.Observe(Environment.ProcessId);
        ExecutionWorker.PublishBusinessProcess(f.DirectoryPath, original);
        string before = FileHash(path);
        Assert.Throws<IOException>(() => ExecutionWorker.PublishBusinessProcess(f.DirectoryPath, new JsonObject { ["pid"] = 0 }));
        Assert.Equal(before, FileHash(path));
        JsonAssert.Equal(original, Read(path));
        Assert.Empty(Directory.GetFiles(f.DirectoryPath, "business-process.json.*.pending"));
    }

    private sealed record PausedNumber(int Value, ManualResetEventSlim Entered, ManualResetEventSlim Release, CancellationToken Cancellation);

    private sealed class PausedNumberConverter : JsonConverter<PausedNumber>
    {
        public override PausedNumber Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) => throw new NotSupportedException();
        public override void Write(Utf8JsonWriter writer, PausedNumber value, JsonSerializerOptions options)
        {
            value.Entered.Set();
            if (!value.Release.Wait(TimeSpan.FromSeconds(15), value.Cancellation)) throw new TimeoutException("Writer was not released.");
            writer.WriteNumberValue(value.Value);
        }
    }
}
