using System.Text.Json.Nodes;
using CommandEntry.Tests;
namespace CommandEntry;

[Trait("Suite", "Regression")]
public sealed class CleanupTests
{
    private static string NewDirectory(string name)
    {
        string path = Path.Combine(TestEnvironment.Root, ".codex-command-records", name + "-" + Guid.NewGuid());
        Directory.CreateDirectory(path);
        return path;
    }

    [Theory, Trait("Category", "Integration")]
    [InlineData("exited", false)]
    [InlineData("exited", true)]
    [InlineData("timed_out", false)]
    [InlineData("timed_out", true)]
    [InlineData("cancelled", false)]
    [InlineData("cancelled", true)]
    public async Task CompletionPreservesTerminalStateWhenFinalWriteFails(string terminal, bool failWrite)
    {
        string path = Path.Combine(NewDirectory("csharp-completion"), "result.json");
        var result = new JsonObject { ["state"] = "running" };
        RecordJson.Save(path, result);
        int businessFailures = 0, writes = 0;
        var writeError = new IOException("final_write_failed");
        var observed = await Record.ExceptionAsync(() => ExecutionCleanup.Complete(() =>
        {
            result["state"] = terminal;
            result["operation_result"] = new JsonObject { ["acceptable_exit"] = terminal == "exited" ? true : null };
            result["subgoal"] = new JsonObject { ["status"] = terminal == "exited" ? "confirmed" : "unknown" };
            return Task.CompletedTask;
        }, error =>
        {
            businessFailures++;
            result["state"] = "tool_error";
            return Task.CompletedTask;
        }, () =>
        {
            writes++;
            if (failWrite) throw writeError;
            RecordJson.Save(path, result);
        }));
        Assert.Same(failWrite ? writeError : null, observed);
        Assert.Equal(0, businessFailures);
        Assert.Equal(1, writes);
        Assert.Equal(terminal, result["state"].String());
        Assert.Equal(terminal == "exited" ? (bool?)true : null, result["operation_result"]!["acceptable_exit"]?.GetValue<bool>());
        Assert.Equal(terminal == "exited" ? "confirmed" : "unknown", result["subgoal"]!["status"].String());
        Assert.Equal(failWrite ? "running" : terminal, RecordJson.Read(path)["state"].String());
    }

    [Fact, Trait("Category", "Unit")]
    public async Task BusinessFailureUsesFailureHandlerWithoutSuccessWrite()
    {
        int handled = 0, finalWrites = 0;
        var businessError = new IOException("business_failed");
        await ExecutionCleanup.Complete(() => Task.FromException(businessError), error =>
        {
            Assert.Same(businessError, error);
            handled++;
            return Task.CompletedTask;
        }, () => finalWrites++);
        Assert.Equal(1, handled);
        Assert.Equal(0, finalWrites);
    }

    [Theory, Trait("Category", "Integration")]
    [InlineData("completed", false)]
    [InlineData("completed", true)]
    [InlineData("handled", false)]
    [InlineData("handled", true)]
    [InlineData("unhandled", false)]
    [InlineData("unhandled", true)]
    public async Task PersistenceFailurePreservesPrimaryAndCleanupErrors(string kind, bool failWrite)
    {
        string path = Path.Combine(NewDirectory("csharp-cleanup-failures"), "result.json");
        var result = new JsonObject { ["state"] = "tool_error", ["error"] = ExecutionRecords.Error(new IOException("primary_failure")) };
        Exception? cleanupError = kind == "completed" ? null : kind == "handled"
            ? new TimeoutException("cleanup_timeout") : new IndexOutOfRangeException("cleanup_unhandled");
        var writeError = new IOException("password=synthetic-value");
        int writes = 0;
        var observed = await Record.ExceptionAsync(() => ExecutionCleanup.PersistFailure(result, () => cleanupError is null ? Task.CompletedTask : Task.FromException(cleanupError), () =>
        {
            writes++;
            if (failWrite) throw writeError;
            RecordJson.Save(path, result);
        }));
        Assert.Equal(1, writes);
        Assert.Equal("primary_failure", result["error"]!["reason"].String());
        Assert.Equal(!failWrite, File.Exists(path));
        if (failWrite)
        {
            var failure = Assert.IsType<ExecutionPersistenceFailure>(observed);
            var detail = ExecutionRecords.Error(failure);
            Assert.Equal("execution_state_persistence_failed", detail["reason"].String());
            Assert.Equal("primary_failure", detail["primary_error"]!["reason"].String());
            Assert.Equal(cleanupError is not null, detail["cleanup_error"] is not null);
            Assert.Contains("[REDACTED", detail["persistence_error"]!["reason"].String());
            Assert.DoesNotContain("synthetic-value", detail.ToJsonString());
            if (cleanupError is null) Assert.Same(writeError, failure.InnerException);
            else
            {
                var aggregate = Assert.IsType<AggregateException>(failure.InnerException);
                Assert.Collection(aggregate.InnerExceptions, error => Assert.Same(cleanupError, error), error => Assert.Same(writeError, error));
            }
        }
        else
        {
            Assert.Same(kind == "unhandled" ? cleanupError : null, observed);
            Assert.Equal("primary_failure", RecordJson.Read(path)["error"]!["reason"].String());
        }
    }

    private sealed class ShortReadStream(byte[] bytes) : MemoryStream(bytes)
    {
        public override int Read(Span<byte> buffer) => base.Read(buffer[..Math.Min(7, buffer.Length)]);
    }

    [Fact, Trait("Category", "Unit")]
    public void ShortReadsFillBlockAndPreserveBytesThroughEof()
    {
        byte[] input = new byte[65545];
        Array.Fill(input, (byte)'x');
        input[0] = (byte)'\n'; input[65535] = 0xff;
        using var source = new ShortReadStream(input);
        byte[] block = new byte[65536];
        Assert.Equal(65536, TextRangeReader.ReadBlock(source, block));
        Assert.Equal(input[..65536], block);
        Assert.Equal((byte)255, block[^1]);
        int count = TextRangeReader.ReadBlock(source, block);
        Assert.Equal(9, count);
        Assert.Equal(input[65536..], block[..count]);
        Assert.Equal(0, TextRangeReader.ReadBlock(source, block));
    }

    [Theory, Trait("Category", "Integration")]
    [InlineData("timeout")]
    [InlineData("io")]
    [InlineData("completed")]
    public async Task HandledCleanupErrorsStillPersistPrimaryFailure(string kind)
    {
        var result = new JsonObject { ["state"] = "tool_error",
            ["error"] = new JsonObject { ["kind"] = "OSError", ["reason"] = "primary_failure" },
            ["process"] = new JsonObject { ["exit_code"] = null } };
        string path = Path.Combine(NewDirectory("csharp-cleanup"), "result.json");
        int writes = 0;
        Task Cleanup() => kind switch
        {
            "timeout" => Task.FromException(new TimeoutException("cleanup_timed_out")),
            "io" => Task.FromException(new IOException("cleanup_io_failure")),
            _ => Task.CompletedTask
        };
        await ExecutionCleanup.PersistFailure(result, Cleanup, () => { RecordJson.Save(path, result); writes++; });
        var stored = RecordJson.Read(path);
        Assert.Equal(1, writes);
        Assert.Equal("tool_error", stored["state"].String());
        Assert.Equal("primary_failure", stored["error"]!["reason"].String());
        Assert.Null(stored["process"]!["exit_code"]);
        Assert.Equal(kind != "completed", stored["cleanup_error"] is not null);
    }
}
