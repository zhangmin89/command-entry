using System.Text.Json.Nodes;
using static CommandEntry.RecordJson;

namespace CommandEntry;

// Append-only identity reservations. The lock order is fingerprint claim, then index.
// A reservation is durable before publication/spawn and is never rolled back.
internal sealed class PublicationIndex(string root)
{
    private readonly string path = Path.Combine(root, "publication-index.jsonl");
    private readonly Dictionary<string, Entry> entries = new(StringComparer.Ordinal);
    private long offset;
    private bool loaded;
    private sealed record Entry(long Count, string Id);

    internal Session Open(Func<IEnumerable<(string Path, JsonObject Envelope)>> history)
    {
        FileMutex mutex;
        try { mutex = new(Path.Combine(root, "publication-index.lock")); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        { throw new InvalidRequest("claim_pending_unconfirmed_retry_later"); }
        FileStream? stream = null;
        try
        {
            Require(!loaded || File.Exists(path), "publication_index_missing: preserve claims and recover the original index");
            stream = new(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read);
            Synchronize(stream);
            var session = new Session(this, mutex, stream);
            if (!loaded)
            {
                var legacy = new Dictionary<string, (long Count, string Id, DateTime Time)>(StringComparer.Ordinal);
                foreach (var item in history())
                {
                    string? fingerprint = item.Envelope["content_fingerprint"].Text();
                    if (fingerprint is null || fingerprint.Length != 64 || !fingerprint.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f')) continue;
                    string id = Path.GetFileName(Path.GetDirectoryName(item.Path))!;
                    if (!JsonFields.IsUuid(id)) continue;
                    DateTime time = File.GetLastWriteTimeUtc(item.Path);
                    if (legacy.TryGetValue(fingerprint, out var prior))
                        legacy[fingerprint] = (checked(prior.Count + 1), time > prior.Time ? id : prior.Id, time > prior.Time ? time : prior.Time);
                    else legacy[fingerprint] = (1, id, time);
                }
                foreach (var item in legacy)
                {
                    if (entries.TryGetValue(item.Key, out var indexed) && indexed.Count >= item.Value.Count) continue;
                    string id = item.Value.Id;
                    string claim = Path.Combine(root, "_claims", item.Key, "claim.json");
                    try
                    {
                        string? claimed = Read(claim)["execution_id"].Text();
                        if (JsonFields.IsUuid(claimed)) id = claimed!;
                    }
                    catch (Exception error) when (ExecutionRecords.Handled(error)) { /* ClaimIdentity handles invalid claims. */ }
                    session.Append(item.Key, item.Value.Count, id);
                }
                loaded = true;
            }
            return session;
        }
        catch { stream?.Dispose(); mutex.Dispose(); throw; }
    }

    private void Synchronize(FileStream stream)
    {
        Require(stream.Length >= offset, "publication_index_truncated: preserve evidence for manual recovery");
        if (stream.Length == offset) return;
        stream.Position = stream.Length - 1;
        Require(stream.ReadByte() == '\n', "publication_index_incomplete: preserve evidence for manual recovery");
        stream.Position = offset;
        var updates = new Dictionary<string, Entry>(StringComparer.Ordinal);
        using (var reader = new StreamReader(stream, Utf8, detectEncodingFromByteOrderMarks: false, leaveOpen: true))
        {
            while (reader.ReadLine() is { } line)
            {
                var value = JsonNode.Parse(line).Object();
                Require(value.Int("schema_version", 0) == 1, "publication_index_version_required");
                string fingerprint = value["content_fingerprint"].String();
                string id = value["execution_id"].String();
                long count = value["count"].Integer("publication_index_count_required");
                Require(fingerprint.Length == 64 && fingerprint.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f')
                    && JsonFields.IsUuid(id) && count > 0, "publication_index_entry_invalid");
                Entry? previous = updates.GetValueOrDefault(fingerprint) ?? entries.GetValueOrDefault(fingerprint);
                Require(previous is null || count > previous.Count, "publication_index_count_not_increasing");
                updates[fingerprint] = new(count, id);
            }
        }
        foreach (var pair in updates) entries[pair.Key] = pair.Value;
        offset = stream.Length;
    }

    internal sealed class Session(PublicationIndex index, FileMutex mutex, FileStream stream) : IDisposable
    {
        internal long Count(string fingerprint) => index.entries.GetValueOrDefault(fingerprint)?.Count ?? 0;
        internal string? Latest(string fingerprint) => index.entries.GetValueOrDefault(fingerprint)?.Id;
        internal void Reserve(string fingerprint, string id) => Append(fingerprint, checked(Count(fingerprint) + 1), id);
        internal void Append(string fingerprint, long count, string id)
        {
            byte[] bytes = Packed(new JsonObject { ["schema_version"] = 1, ["content_fingerprint"] = fingerprint,
                ["count"] = count, ["execution_id"] = id });
            stream.Position = stream.Length;
            stream.Write(bytes); stream.WriteByte((byte)'\n'); stream.Flush(flushToDisk: true);
            index.entries[fingerprint] = new(count, id);
            index.offset = stream.Length;
        }
        public void Dispose() { stream.Dispose(); mutex.Dispose(); }
    }
}
