using System.Text.Json.Nodes;
using CommandEntry;
using static CommandEntry.RecordJson;

namespace CommandEntry.Tests;

internal static class GapRegressionTests
{
    private static string NewDirectory()
    {
        string path = Path.Combine(TestRunner.Root, ".codex-command-records", "csharp-gap-" + Guid.NewGuid());
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
        Check.Equal(2L, session.Count(Fingerprint));
        return index;
    }
    private static void RejectedUnchanged(PublicationIndex index, string root, string reason)
    {
        string hash = FileHash(Journal(root));
        Check.Throws<InvalidRequest>(() => { using var session = index.Open(EmptyHistory); }, reason);
        Check.Equal(hash, FileHash(Journal(root)));
    }

    [Case]
    internal static void IndexMissingAfterLoadDoesNotRecreateEvidence()
    {
        foreach (bool populated in new[] { false, true })
        {
            string root = NewDirectory();
            var index = populated ? Seed(root) : new PublicationIndex(root);
            using (var session = index.Open(EmptyHistory)) Check.Equal(populated ? 2L : 0L, session.Count(Fingerprint));
            string original = Journal(root) + ".original", hash = FileHash(Journal(root));
            File.Move(Journal(root), original);
            Check.Throws<InvalidRequest>(() => { using var session = index.Open(EmptyHistory); }, "publication_index_missing");
            Check.True(!Path.Exists(Journal(root)), "Missing live index must not be recreated");
            Check.Equal(hash, FileHash(original));
        }
    }

    [Case]
    internal static void IndexTruncatedAtCompleteRecordIsRejected()
    {
        string root = NewDirectory(); var index = Seed(root);
        string journal = Journal(root), original = journal + ".original";
        File.Copy(journal, original);
        byte[] bytes = File.ReadAllBytes(original);
        int firstRecord = Array.IndexOf(bytes, (byte)'\n') + 1;
        Check.True(firstRecord > 0 && firstRecord < bytes.Length);
        File.WriteAllBytes(journal, bytes[..firstRecord]);
        RejectedUnchanged(index, root, "publication_index_truncated");
        Check.True(File.ReadAllBytes(original).AsSpan().SequenceEqual(bytes));
    }

    [Case]
    internal static void IndexCountMustIncreaseAcrossCachedAndNewEntries()
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
        Check.Equal(3L, session.Count(Fingerprint));
        Check.Equal(next["execution_id"].Text(), session.Latest(Fingerprint));
    }

    [Case]
    internal static void IndexUnsupportedVersionIsRejected()
    {
        string root = NewDirectory(); var index = Seed(root);
        var entry = Entry(3); entry["schema_version"] = 2; Append(root, entry);
        RejectedUnchanged(index, root, "publication_index_version_required");
        RejectedUnchanged(new PublicationIndex(root), root, "publication_index_version_required");
    }

    [Case]
    internal static void IndexInvalidIdentityAndCountsAreRejected()
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

    [Case]
    internal static void OversizedLineIsDiscardedAndNextLineSurvives()
    {
        foreach (bool fragmented in new[] { false, true })
        {
            string path = Path.Combine(NewDirectory(), "output.txt");
            using var capture = new OutputCapture(path);
            if (fragmented)
            {
                capture.Feed(Utf8.GetBytes(new string('x', 16384)));
                capture.Feed(Utf8.GetBytes("x"));
                Check.Equal(1L, capture.Metadata()["missing_lines"]!.GetValue<long>());
                for (int i = 0; i < 10; i++) capture.Feed(Utf8.GetBytes(new string('x', 8192)));
                capture.Feed(Utf8.GetBytes("\nok\n"), final: true);
            }
            else capture.Feed(Utf8.GetBytes(new string('x', 20000) + "\nok\n"), final: true);
            var metadata = capture.Metadata();
            Check.True(File.ReadAllText(path, Utf8) == "ok\n", "Oversized line must be discarded; retain only the next line");
            Check.Equal("ok\n", metadata["preview_head"].Text());
            Check.Equal("ok\n", metadata["preview_tail"].Text());
            Check.Equal(1L, metadata["missing_lines"]!.GetValue<long>());
            Check.Json(new JsonArray(new JsonArray(1, 1)), metadata["missing_decoded_line_ranges"]);
        }
    }

    [Case]
    internal static void LineLimitCountsRunesIncludingLineEnding()
    {
        foreach (bool newline in new[] { false, true })
        foreach (int length in new[] { 16383, 16384, 16385 })
        {
            string path = Path.Combine(NewDirectory(), "output.txt");
            string text = string.Concat(Enumerable.Repeat("😀", length - (newline ? 1 : 0))) + (newline ? "\n" : "");
            using var capture = new OutputCapture(path);
            capture.Feed(Utf8.GetBytes(text), final: true);
            bool retained = length <= 16384;
            Check.True(File.ReadAllText(path, Utf8) == (retained ? text : ""),
                $"Line limit mismatch: runes={length}, newline={newline}, expectedRetained={retained}");
            var metadata = capture.Metadata();
            Check.Equal(retained ? 0L : 1L, metadata["missing_lines"]!.GetValue<long>());
            Check.Equal(retained ? string.Concat(Enumerable.Repeat("😀", 512)) : "", metadata["preview_head"].Text());
        }
    }

    [Case]
    internal static void InvalidUtf8IsReportedAndReplaced()
    {
        foreach (byte[] bytes in new[] { new byte[] { 0x41, 0xff, 0xfe, 0x42, 0x0a }, new byte[] { 0x41, 0xf0, 0x9f } })
        {
            string path = Path.Combine(NewDirectory(), "output.txt");
            using var capture = new OutputCapture(path);
            capture.Feed(bytes);
            capture.Feed([], final: true);
            string expected = bytes.Length == 5 ? "A\ufffd\ufffdB\n" : "A\ufffd";
            Check.Equal(expected, File.ReadAllText(path, Utf8));
            var metadata = capture.Metadata();
            Check.True(metadata["decode_error_count"]!.GetValue<long>() > 0);
            Check.Equal(true, metadata["decoding_loss"]!.GetValue<bool>());
            Check.Equal(expected, metadata["preview_tail"].Text());
        }
    }

    [Case]
    internal static void AstralCharacterCrossesInternalByteBoundary()
    {
        string path = Path.Combine(NewDirectory(), "output.txt"), text = new string('x', 8190) + "😀";
        using var capture = new OutputCapture(path);
        capture.Feed(Utf8.GetBytes(text), final: true);
        var metadata = capture.Metadata();
        Check.Equal(text, File.ReadAllText(path, Utf8));
        Check.Equal(new string('x', 511) + "😀", metadata["preview_tail"].Text());
        Check.Equal(0L, metadata["decode_error_count"]!.GetValue<long>());
        Check.Equal(false, metadata["decoding_loss"]!.GetValue<bool>());
    }

    [Case]
    internal static void PreviewCompletenessRequiresFinalWithinByteLimitWithoutMissing()
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
            Check.Equal(final, metadata["capture_complete"]!.GetValue<bool>());
            Check.Equal(quota == 1 ? 1L : 0L, metadata["missing_lines"]!.GetValue<long>());
            Check.Equal(expected, metadata["preview_complete"]!.GetValue<bool>());
        }
    }

    [Case]
    internal static void OpenProcessInvalidParameterMapsToDeadWithoutIdentity()
    {
        // PID 0 deterministically produces ERROR_INVALID_PARAMETER; this tests the
        // error mapping, not the lifecycle of a real terminated business process.
        var observation = WindowsProcess.Observe(0);
        Check.Equal(false, observation["alive"]!.GetValue<bool>());
        Check.True(observation["creation_time"] is null);
        Check.True(observation["exit_code"] is null);
    }
}
