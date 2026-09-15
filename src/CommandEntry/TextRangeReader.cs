using System.Text;
using System.Text.Json.Nodes;
using static CommandEntry.RecordJson;

namespace CommandEntry;

internal static class TextRangeReader
{
    internal static JsonObject Read(JsonObject form, JsonObject policy)
    {
        form.Known(["file", "start_line", "max_lines", "encoding"]);
        string path = BusinessPaths.Resolve(form["file"].String("file_required"), "file");
        var roots = policy["read_roots"] is null ? policy["working_roots"].Array() : policy["read_roots"].Array();
        var expanded = roots.SelectMany(r => r.Text() == "@working_roots" ? policy["working_roots"].Array().Select(n => n.String()) : [r.String()]);
        Require(expanded.Any(r => BusinessPaths.Within(path, BusinessPaths.Resolve(r))), "file_outside_read_roots");
        int start = form.Int("start_line", 1), count = form.Int("max_lines", 100), quota = policy.Int("read_quota_bytes", 65536);
        Require(start >= 1, "invalid_start_line");
        Require(count is >= 1 and <= 1000, "max_lines_range_1_1000");
        string? encoding = form["encoding"].Text();
        Require(form["encoding"] is null || encoding is "utf-8" or "utf-8-sig" or "gbk" or "utf-16" or "utf-16-le", "unsupported_encoding");
        using var source = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        long totalBytes = source.Length;
        byte[] prefix = new byte[Math.Min(4096, totalBytes)];
        source.ReadExactly(prefix);
        bool utf8Bom = prefix.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf });
        bool littleBom = prefix.AsSpan().StartsWith(new byte[] { 0xff, 0xfe });
        bool bigBom = prefix.AsSpan().StartsWith(new byte[] { 0xfe, 0xff });
        encoding ??= utf8Bom ? "utf-8-sig" : littleBom || bigBom ? "utf-16" : "utf-8";
        int skip = 0;
        if (encoding == "utf-8-sig") { encoding = "utf-8"; if (utf8Bom) skip = 3; }
        else if (encoding == "utf-16") { encoding = bigBom ? "utf-16-be" : "utf-16-le"; if (littleBom || bigBom) skip = 2; }
        source.Position = skip;
        var decoder = TextCodec.Get(encoding).GetDecoder();
        byte[] bytes = new byte[65536];
        char[] characters = new char[4];
        int byteIndex = 0, byteCount = 0, charIndex = 0, charCount = 0;
        bool eof = false;
        int Next()
        {
            while (charIndex >= charCount)
            {
                if (eof) return -1;
                if (byteIndex == byteCount) { byteCount = source.Read(bytes); byteIndex = 0; }
                bool final = byteCount == 0;
                charCount = decoder.GetChars(final ? ReadOnlySpan<byte>.Empty : bytes.AsSpan(byteIndex++, 1), characters, final);
                charIndex = 0;
                eof = final;
            }
            return characters[charIndex++];
        }
        var payload = new StringBuilder();
        var pending = new StringBuilder();
        int lineIndex = 0, served = 0, servedBytes = 0, pendingBytes = 0;
        bool pendingCr = false, hasLine = false, stopped = false;
        JsonObject? error = null;
        string? decodeWarning = null;
        void FinishLine()
        {
            lineIndex++;
            if (lineIndex >= start)
            {
                string line = pending.ToString();
                int size = Utf8.GetByteCount(line);
                if (size > quota) error = new() { ["error"] = "single_line_exceeds_quota", ["line_number"] = lineIndex, ["line_bytes"] = size, ["quota_bytes"] = quota };
                else if (servedBytes + size > quota) stopped = true;
                else { payload.Append(line); served++; servedBytes += size; }
            }
            pending.Clear(); pendingBytes = 0; hasLine = false; pendingCr = false;
        }
        try
        {
            while (!stopped && error is null)
            {
                int next = Next();
                if (next < 0) { if (hasLine) FinishLine(); break; }
                char c = (char)next;
                if (pendingCr && c != '\n')
                {
                    FinishLine();
                    if (served >= count || stopped || error is not null) { stopped = true; break; }
                }
                hasLine = true;
                if (lineIndex + 1 >= start)
                {
                    pending.Append(c);
                    pendingBytes += char.IsHighSurrogate(c) ? 0 : char.IsLowSurrogate(c) ? 4 : c < 0x80 ? 1 : c < 0x800 ? 2 : 3;
                }
                if (TextCodec.IsEnding(c) && c != '\r')
                {
                    FinishLine();
                    if (served >= count) { stopped = true; break; }
                }
                else pendingCr = c == '\r';
                if (pendingBytes > quota)
                    error = new() { ["error"] = "single_line_exceeds_quota", ["line_number"] = lineIndex + 1,
                        ["line_bytes_at_least"] = pendingBytes, ["quota_bytes"] = quota };
            }
        }
        catch (DecoderFallbackException failure)
        {
            return error ?? new JsonObject { ["error"] = "decoding_failed_strict", ["encoding_tried"] = encoding,
                ["detail"] = failure.Message[..Math.Min(200, failure.Message.Length)],
                ["suggested_encodings"] = new JsonArray(new[] { "gbk", "utf-16-le", "utf-16", "utf-8" }
                    .Where(name => CanDecode(prefix, name)).Select(name => (JsonNode?)JsonValue.Create(name)).ToArray()) };
        }
        if (error is not null) return error;
        if (stopped)
        {
            // Python checks the whole loaded block. Do not read another block,
            // flush an incomplete trailing character, or accumulate later lines.
            try
            {
                while (byteIndex < byteCount)
                    decoder.GetChars(bytes.AsSpan(byteIndex++, 1), characters, flush: false);
            }
            catch (DecoderFallbackException failure)
            {
                decodeWarning = "The requested range was fully served; a strict decode fault exists beyond it: "
                    + failure.Message[..Math.Min(150, failure.Message.Length)];
            }
        }
        var result = new JsonObject
        {
            ["file"] = path, ["encoding_used"] = encoding, ["text"] = payload.ToString(), ["start_line"] = start,
            ["lines_served"] = served, ["total_lines"] = eof && !stopped ? lineIndex : null,
            ["total_lines_known"] = eof && !stopped, ["total_bytes"] = totalBytes, ["remaining"] = stopped,
            ["next_start_line"] = start + served, ["decoding_loss"] = false
        };
        if (decodeWarning is not null) result["decode_warning"] = decodeWarning;
        return result;
    }
    private static bool CanDecode(byte[] bytes, string encoding)
    {
        try { TextCodec.Get(encoding).GetString(bytes); return true; }
        catch (DecoderFallbackException) { return false; }
    }
}
