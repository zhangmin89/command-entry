using System.Text.Json.Nodes;
using CommandEntry;
using static CommandEntry.RecordJson;

namespace CommandEntry.Tests;

[Trait("Suite", "Regression")]
public sealed class GapRegressionTests
{
    private static string NewDirectory()
    {
        string path = Path.Combine(TestEnvironment.Root, ".codex-command-records", "csharp-gap-" + Guid.NewGuid());
        Directory.CreateDirectory(path);
        return path; // Synthetic evidence is retained, including pre-damage copies.
    }

    private const string Fingerprint = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static JsonObject Entry(long count) => new()
    {
        ["schema_version"] = 1, ["content_fingerprint"] = Fingerprint,
        ["execution_id"] = Guid.NewGuid().ToString(), ["count"] = count
    };
    private static IEnumerable<(string Path, JsonObject Envelope)> EmptyHistory() => [];
    private static string Journal(string root) => Path.Combine(root, "publication-index.jsonl");
    private static void Append(string root, JsonObject entry) => File.AppendAllText(Journal(root), Utf8.GetString(Packed(entry)) + "\n", Utf8);
    private static PublicationIndex Seed(string root)
    {
        Append(root, Entry(1)); Append(root, Entry(2));
        var index = new PublicationIndex(root);
        using var session = index.Open(EmptyHistory);
        Assert.Equal(2L, session.Count(Fingerprint));
        return index;
    }
    private static void RejectedUnchanged(PublicationIndex index, string root, string reason)
    {
        string hash = FileHash(Journal(root));
        TestAssert.Throws<InvalidRequest>(() => { using var session = index.Open(EmptyHistory); }, reason);
        Assert.Equal(hash, FileHash(Journal(root)));
    }

    [Fact, Trait("Category", "Integration")]
    public void IndexMissingAfterLoadDoesNotRecreateEvidence()
    {
        foreach (bool populated in new[] { false, true })
        {
            string root = NewDirectory();
            var index = populated ? Seed(root) : new PublicationIndex(root);
            using (var session = index.Open(EmptyHistory)) Assert.Equal(populated ? 2L : 0L, session.Count(Fingerprint));
            string original = Journal(root) + ".original", hash = FileHash(Journal(root));
            File.Move(Journal(root), original);
            TestAssert.Throws<InvalidRequest>(() => { using var session = index.Open(EmptyHistory); }, "publication_index_missing");
            Assert.False(Path.Exists(Journal(root)), "Missing live index must not be recreated");
            Assert.Equal(hash, FileHash(original));
        }
    }

    [Fact, Trait("Category", "Integration")]
    public void IndexTruncatedAtCompleteRecordIsRejected()
    {
        string root = NewDirectory(); var index = Seed(root);
        string journal = Journal(root), original = journal + ".original";
        File.Copy(journal, original);
        byte[] bytes = File.ReadAllBytes(original);
        int firstRecord = Array.IndexOf(bytes, (byte)'\n') + 1;
        Assert.True(firstRecord > 0 && firstRecord < bytes.Length);
        File.WriteAllBytes(journal, bytes[..firstRecord]);
        RejectedUnchanged(index, root, "publication_index_truncated");
        Assert.True(File.ReadAllBytes(original).AsSpan().SequenceEqual(bytes));
    }

    [Fact, Trait("Category", "Integration")]
    public void IndexCountMustIncreaseAcrossCachedAndNewEntries()
    {
        foreach (long count in new[] { 2L, 1L })
        {
            string root = NewDirectory(); var index = Seed(root);
            Append(root, Entry(count));
            RejectedUnchanged(index, root, "publication_index_count_not_increasing");
            RejectedUnchanged(new PublicationIndex(root), root, "publication_index_count_not_increasing");
        }
        string validRoot = NewDirectory(); var valid = Seed(validRoot); var next = Entry(3);
        Append(validRoot, next);
        using var session = valid.Open(EmptyHistory);
        Assert.Equal(3L, session.Count(Fingerprint));
        Assert.Equal(next["execution_id"].Text(), session.Latest(Fingerprint));
    }

    [Fact, Trait("Category", "Integration")]
    public void IndexUnsupportedVersionIsRejected()
    {
        string root = NewDirectory(); var index = Seed(root);
        var entry = Entry(3); entry["schema_version"] = 3; Append(root, entry);
        RejectedUnchanged(index, root, "publication_index_version_required");
        RejectedUnchanged(new PublicationIndex(root), root, "publication_index_version_required");
    }

    [Fact, Trait("Category", "Integration")]
    public void IndexInvalidIdentityAndCountsAreRejected()
    {
        foreach (var (field, value) in new (string, JsonNode)[]
        {
            ("content_fingerprint", JsonValue.Create(new string('a', 63))!),
            ("content_fingerprint", JsonValue.Create(new string('a', 65))!),
            ("content_fingerprint", JsonValue.Create(new string('g', 64))!),
            ("execution_id", JsonValue.Create("not-a-uuid")!),
            ("count", JsonValue.Create(0)!), ("count", JsonValue.Create(-1)!)
        })
        {
            string root = NewDirectory(); var index = Seed(root);
            var entry = Entry(3); entry[field] = value; Append(root, entry);
            RejectedUnchanged(index, root, "publication_index_entry_invalid");
            RejectedUnchanged(new PublicationIndex(root), root, "publication_index_entry_invalid");
        }
    }

    [Fact, Trait("Category", "Integration")]
    public void OversizedLineIsDiscardedAndNextLineSurvives()
    {
        foreach (bool fragmented in new[] { false, true })
        {
            string path = Path.Combine(NewDirectory(), "output.txt");
            using var capture = new OutputCapture(path);
            if (fragmented)
            {
                capture.Feed(Utf8.GetBytes(new string('x', 16384)));
                capture.Feed(Utf8.GetBytes("x"));
                Assert.Equal(1L, capture.Metadata()["missing_lines"]!.GetValue<long>());
                for (int i = 0; i < 10; i++) capture.Feed(Utf8.GetBytes(new string('x', 8192)));
                capture.Feed(Utf8.GetBytes("\nok\n"), final: true);
            }
            else capture.Feed(Utf8.GetBytes(new string('x', 20000) + "\nok\n"), final: true);
            var metadata = capture.Metadata();
            Assert.True(File.ReadAllText(path, Utf8) == "ok\n", "Oversized line must be discarded; retain only the next line");
            Assert.Equal("ok\n", metadata["preview_head"].Text());
            Assert.Equal("ok\n", metadata["preview_tail"].Text());
            Assert.Equal(1L, metadata["missing_lines"]!.GetValue<long>());
            JsonAssert.Equal(new JsonArray(new JsonArray(1, 1)), metadata["missing_decoded_line_ranges"]);
        }
    }

    [Fact, Trait("Category", "Integration")]
    public void LineLimitCountsRunesIncludingLineEnding()
    {
        foreach (bool newline in new[] { false, true })
        foreach (int length in new[] { 16383, 16384, 16385 })
        {
            string path = Path.Combine(NewDirectory(), "output.txt");
            string text = string.Concat(Enumerable.Repeat("😀", length - (newline ? 1 : 0))) + (newline ? "\n" : "");
            using var capture = new OutputCapture(path);
            capture.Feed(Utf8.GetBytes(text), final: true);
            bool retained = length <= 16384;
            Assert.True(File.ReadAllText(path, Utf8) == (retained ? text : ""),
                $"Line limit mismatch: runes={length}, newline={newline}, expectedRetained={retained}");
            var metadata = capture.Metadata();
            Assert.Equal(retained ? 0L : 1L, metadata["missing_lines"]!.GetValue<long>());
            Assert.Equal(retained ? string.Concat(Enumerable.Repeat("😀", 512)) : "", metadata["preview_head"].Text());
        }
    }

    [Fact, Trait("Category", "Integration")]
    public void InvalidUtf8IsReportedAndReplaced()
    {
        foreach (byte[] bytes in new[] { new byte[] { 0x41, 0xff, 0xfe, 0x42, 0x0a }, new byte[] { 0x41, 0xf0, 0x9f } })
        {
            string path = Path.Combine(NewDirectory(), "output.txt");
            using var capture = new OutputCapture(path);
            capture.Feed(bytes);
            capture.Feed([], final: true);
            string expected = bytes.Length == 5 ? "A\ufffd\ufffdB\n" : "A\ufffd";
            Assert.Equal(expected, File.ReadAllText(path, Utf8));
            var metadata = capture.Metadata();
            Assert.True(metadata["decode_error_count"]!.GetValue<long>() > 0);
            Assert.True(metadata["decoding_loss"]!.GetValue<bool>());
            Assert.Equal(expected, metadata["preview_tail"].Text());
        }
    }

    [Fact, Trait("Category", "Integration")]
    public void AstralCharacterCrossesInternalByteBoundary()
    {
        string path = Path.Combine(NewDirectory(), "output.txt"), text = new string('x', 8190) + "😀";
        using var capture = new OutputCapture(path);
        capture.Feed(Utf8.GetBytes(text), final: true);
        var metadata = capture.Metadata();
        Assert.Equal(text, File.ReadAllText(path, Utf8));
        Assert.Equal(new string('x', 511) + "😀", metadata["preview_tail"].Text());
        Assert.Equal(0L, metadata["decode_error_count"]!.GetValue<long>());
        Assert.False(metadata["decoding_loss"]!.GetValue<bool>());
    }

    [Fact, Trait("Category", "Integration")]
    public void PreviewCompletenessRequiresFinalWithinByteLimitWithoutMissing()
    {
        foreach (var (text, final, quota, expected) in new[]
        {
            ("hi\n", true, 1024, true), ("hi\n", false, 1024, false), ("hi\n", true, 1, false),
            (new string('x', 511), true, 1024, true), (new string('x', 512), true, 1024, true),
            (new string('x', 513), true, 1024, false), (new string('x', 600), true, 1024, false),
            (string.Concat(Enumerable.Repeat("😀", 129)), true, 1024, false)
        })
        {
            string path = Path.Combine(NewDirectory(), "output.txt");
            using var capture = new OutputCapture(path, quota: quota);
            capture.Feed(Utf8.GetBytes(text), final: final);
            var metadata = capture.Metadata();
            Assert.Equal(final, metadata["capture_complete"]!.GetValue<bool>());
            Assert.Equal(quota == 1 ? 1L : 0L, metadata["missing_lines"]!.GetValue<long>());
            Assert.Equal(expected, metadata["preview_complete"]!.GetValue<bool>());
        }
    }

    [Fact, Trait("Category", "Integration")]
    public void OpenProcessInvalidParameterMapsToDeadWithoutIdentity()
    {
        // PID 0 deterministically produces ERROR_INVALID_PARAMETER; this tests the
        // error mapping, not the lifecycle of a real terminated business process.
        var observation = WindowsProcess.Observe(0);
        Assert.False(observation["alive"]!.GetValue<bool>());
        Assert.Null(observation["creation_time"]);
        Assert.Null(observation["exit_code"]);
    }
}
