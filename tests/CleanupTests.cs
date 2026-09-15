using System.Text.Json.Nodes;
using CommandEntry.Tests;
namespace CommandEntry;

internal static class CleanupTests
{
    private static string Root => TestRunner.Root;
    private static string Text(JsonNode? node) => RecordJson.Utf8.GetString(RecordJson.Packed(node));
    private static void Check(string label, string actual, string expected)
    { if (actual != expected) throw new Exception(label + ": expected <" + expected + ">, actual <" + actual + ">"); }

    [CommandEntry.Tests.Case]
    private static void CheckCompletion()
    {
        string directory = Path.Combine(Root, ".codex-command-records", "csharp-completion-" + Guid.NewGuid());
        Directory.CreateDirectory(directory);
        foreach (string terminal in new[] { "exited", "timed_out", "cancelled" })
        foreach (bool failWrite in new[] { false, true })
        {
            string label = $"completion.{terminal}.{failWrite}";
            string path = Path.Combine(directory, terminal + "-" + failWrite + ".json");
            var result = new JsonObject { ["state"] = "running" };
            RecordJson.Save(path, result);
            int businessFailures = 0, writes = 0;
            var writeError = new IOException("final_write_failed");
            Exception? observed = null;
            try
            {
                ExecutionCleanup.Complete(() =>
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
                }).GetAwaiter().GetResult();
            }
            catch (Exception error) { observed = error; }
            Check(label + ".exception", ReferenceEquals(observed, failWrite ? writeError : null).ToString(), "True");
            Check(label + ".business-failures", businessFailures.ToString(), "0");
            Check(label + ".writes", writes.ToString(), "1");
            Check(label + ".state", result["state"].String(), terminal);
            Check(label + ".acceptable", Text(result["operation_result"]!["acceptable_exit"]!), terminal == "exited" ? "true" : "null");
            Check(label + ".subgoal", result["subgoal"]!["status"].String(), terminal == "exited" ? "confirmed" : "unknown");
            Check(label + ".stored", RecordJson.Read(path)["state"].String(), failWrite ? "running" : terminal);
        }
        int handled = 0, finalWrites = 0;
        var businessError = new IOException("business_failed");
        ExecutionCleanup.Complete(() => Task.FromException(businessError), error =>
        {
            Check("completion.business-error", ReferenceEquals(error, businessError).ToString(), "True");
            handled++;
            return Task.CompletedTask;
        }, () => finalWrites++).GetAwaiter().GetResult();
        Check("completion.business-handler", handled.ToString(), "1");
        Check("completion.no-success-write", finalWrites.ToString(), "0");
    }

    [CommandEntry.Tests.Case]
    private static void CheckCleanupFailures()
    {
        string directory = Path.Combine(Root, ".codex-command-records", "csharp-cleanup-failures-" + Guid.NewGuid());
        Directory.CreateDirectory(directory);
        foreach (string kind in new[] { "completed", "handled", "unhandled" })
        foreach (bool failWrite in new[] { false, true })
        {
            string label = $"cleanup-failure.{kind}.{failWrite}";
            string path = Path.Combine(directory, kind + "-" + failWrite + ".json");
            var result = new JsonObject { ["state"] = "tool_error", ["error"] = ExecutionRecords.Error(new IOException("primary_failure")) };
            Exception? cleanupError = kind == "completed" ? null : kind == "handled"
                ? new TimeoutException("cleanup_timeout") : new IndexOutOfRangeException("cleanup_unhandled");
            var writeError = new IOException("password=synthetic-value");
            Exception? observed = null;
            int writes = 0;
            try
            {
                ExecutionCleanup.PersistFailure(result, () => cleanupError is null ? Task.CompletedTask : Task.FromException(cleanupError), () =>
                {
                    writes++;
                    if (failWrite) throw writeError;
                    RecordJson.Save(path, result);
                }).GetAwaiter().GetResult();
            }
            catch (Exception error) { observed = error; }
            Check(label + ".writes", writes.ToString(), "1");
            Check(label + ".primary", result["error"]!["reason"].String(), "primary_failure");
            Check(label + ".stored", File.Exists(path).ToString(), (!failWrite).ToString());
            if (failWrite)
            {
                Check(label + ".failure-type", (observed is ExecutionPersistenceFailure).ToString(), "True");
                var detail = ExecutionRecords.Error(observed!);
                Check(label + ".reason", detail["reason"].String(), "execution_state_persistence_failed");
                Check(label + ".preserved-primary", detail["primary_error"]!["reason"].String(), "primary_failure");
                Check(label + ".cleanup", (detail["cleanup_error"] is not null).ToString(), (cleanupError is not null).ToString());
                Check(label + ".redaction", detail["persistence_error"]!["reason"].String().Contains("[REDACTED").ToString(), "True");
                Check(label + ".no-secret", Text(detail).Contains("synthetic-value").ToString(), "False");
                Check(label + ".inner", (cleanupError is null ? ReferenceEquals(observed!.InnerException, writeError)
                    : observed!.InnerException is AggregateException aggregate && ReferenceEquals(aggregate.InnerExceptions[0], cleanupError)
                        && ReferenceEquals(aggregate.InnerExceptions[1], writeError)).ToString(), "True");
            }
            else
            {
                Check(label + ".escape", ReferenceEquals(observed, kind == "unhandled" ? cleanupError : null).ToString(), "True");
                Check(label + ".stored-primary", RecordJson.Read(path)["error"]!["reason"].String(), "primary_failure");
            }
        }
    }

    private sealed class ShortReadStream(byte[] bytes) : MemoryStream(bytes)
    {
        public override int Read(Span<byte> buffer) => base.Read(buffer[..Math.Min(7, buffer.Length)]);
    }

    [CommandEntry.Tests.Case]
    private static void CheckShortReads()
    {
        byte[] input = new byte[65545];
        Array.Fill(input, (byte)'x');
        input[0] = (byte)'\n'; input[65535] = 0xff;
        using var source = new ShortReadStream(input);
        byte[] block = new byte[65536];
        int count = TextRangeReader.ReadBlock(source, block);
        Check("short-read.full-block", count.ToString(), "65536");
        Check("short-read.contents", block.AsSpan().SequenceEqual(input.AsSpan(0, 65536)).ToString(), "True");
        Check("short-read.warning-byte", block[^1].ToString(), "255");
        count = TextRangeReader.ReadBlock(source, block);
        Check("short-read.final-block", count.ToString(), "9");
        Check("short-read.final-contents", block.AsSpan(0, count).SequenceEqual(input.AsSpan(65536)).ToString(), "True");
        Check("short-read.eof", TextRangeReader.ReadBlock(source, block).ToString(), "0");
    }

    [CommandEntry.Tests.Case]
    private static void CheckCleanup()
    {
        string directory = Path.Combine(Root, ".codex-command-records", "csharp-cleanup-" + Guid.NewGuid());
        Directory.CreateDirectory(directory);
        foreach (string kind in new[] { "timeout", "io", "completed" })
        {
            var result = new JsonObject { ["state"] = "tool_error",
                ["error"] = new JsonObject { ["kind"] = "OSError", ["reason"] = "primary_failure" },
                ["process"] = new JsonObject { ["exit_code"] = null } };
            string path = Path.Combine(directory, kind + ".json");
            int writes = 0;
            Task Cleanup() => kind switch
            {
                "timeout" => Task.FromException(new TimeoutException("cleanup_timed_out")),
                "io" => Task.FromException(new IOException("cleanup_io_failure")),
                _ => Task.CompletedTask
            };
            ExecutionCleanup.PersistFailure(result, Cleanup, () => { RecordJson.Save(path, result); writes++; }).GetAwaiter().GetResult();
            var stored = RecordJson.Read(path);
            Check("cleanup." + kind + ".persist", writes.ToString(), "1");
            Check("cleanup." + kind + ".state", stored["state"].String(), "tool_error");
            Check("cleanup." + kind + ".primary", stored["error"]!["reason"].String(), "primary_failure");
            Check("cleanup." + kind + ".exit", Text(stored["process"]!["exit_code"]!), "null");
            Check("cleanup." + kind + ".secondary", (stored["cleanup_error"] is not null).ToString(), (kind != "completed").ToString());
        }
    }
}
