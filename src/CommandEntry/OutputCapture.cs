using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace CommandEntry;

internal sealed partial class OutputCapture : IDisposable
{
    private readonly object gate = new();
    private readonly string? path;
    private readonly int quota;
    private readonly Decoder decoder;
    private FileStream? file;
    private long total, retained, errors, missing, lineNumber;
    private bool complete, redacted, discardLine, privateKey;
    private string? storageError;
    private string pending = "", head = "", tail = "";
    private readonly List<(long Start, long End)> ranges = [];

    internal OutputCapture(string? path, string encoding = "utf-8", int quota = 1048576)
    {
        this.path = path;
        this.quota = quota;
        var codec = (Encoding)TextCodec.Get(encoding).Clone();
        codec.DecoderFallback = new CountingFallback(() => errors++);
        decoder = codec.GetDecoder();
        if (path is not null)
            try { file = new(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read); }
            catch (IOException error) { storageError = error.GetType().Name; }
            catch (UnauthorizedAccessException error) { storageError = error.GetType().Name; }
    }

    [GeneratedRegex(@"(?:password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|cookie|secret)\s*[=:]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex Credential();
    [GeneratedRegex(@"\bBearer\s+\S+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex Bearer();
    [GeneratedRegex(@"\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{16,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)")]
    private static partial Regex Token();

    internal static string RedactLine(string line) => Credential().IsMatch(line)
        ? "[REDACTED credential line]\n" : Token().Replace(Bearer().Replace(line, "[REDACTED bearer]"), "[REDACTED]");

    internal static string Slice(string text, long start, long count) =>
        string.Concat(text.EnumerateRunes().Skip((int)Math.Min(start, int.MaxValue)).Take((int)Math.Min(count, int.MaxValue)).Select(r => r.ToString()));
    internal static int Length(string text) => text.EnumerateRunes().Count();

    private void Missing(long line)
    {
        missing++;
        if (ranges.Count > 0 && ranges[^1].End + 1 >= line) ranges[^1] = (ranges[^1].Start, line);
        else ranges.Add((line, line));
    }

    private void Accept(string line)
    {
        if (line.Contains("-----BEGIN ") && line.Contains("PRIVATE KEY-----")) privateKey = true;
        string safe;
        if (privateKey)
        {
            if (line.Contains("-----END ") && line.Contains("PRIVATE KEY-----")) privateKey = false;
            safe = "[REDACTED private key material]\n";
        }
        else safe = RedactLine(line);
        redacted |= safe != line;
        head += Slice(safe, 0, Math.Max(0, 512 - Length(head)));
        tail += safe;
        tail = Slice(tail, Math.Max(0, Length(tail) - 512), 512);
        byte[] bytes = RecordJson.Utf8.GetBytes(safe);
        if (file is null || retained + bytes.Length > quota) { Missing(lineNumber); return; }
        try { file.Write(bytes); file.Flush(); retained += bytes.Length; }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            storageError = error.GetType().Name;
            file.Dispose(); file = null;
            Missing(lineNumber);
        }
    }

    internal void Feed(ReadOnlySpan<byte> bytes, bool final = false)
    {
        lock (gate)
        {
            total += bytes.Length;
            char[] buffer = new char[bytes.Length * 2 + 4];
            int count = decoder.GetChars(bytes, buffer, final);
            foreach (string fragment in TextCodec.Lines(new string(buffer, 0, count)))
            {
                bool ended = fragment.EndsWith('\n') || fragment.EndsWith('\r');
                if (!discardLine)
                {
                    pending += fragment;
                    if (Length(pending) > 16384)
                    {
                        pending = ""; discardLine = true; Missing(lineNumber + 1);
                    }
                }
                if (!ended) continue;
                lineNumber++;
                if (!discardLine) Accept(pending);
                pending = ""; discardLine = false;
            }
            if (final)
            {
                if (pending.Length > 0 && !discardLine) { lineNumber++; Accept(pending); }
                pending = ""; complete = true;
                file?.Dispose(); file = null;
            }
        }
    }

    internal async Task DrainAsync(Stream pipe)
    {
        byte[] buffer = new byte[8192];
        try
        {
            int count;
            while ((count = await pipe.ReadAsync(buffer)) != 0) Feed(buffer.AsSpan(0, count));
            Feed([], final: true);
        }
        finally { await pipe.DisposeAsync(); }
    }

    internal JsonObject Metadata()
    {
        lock (gate)
            return new()
            {
                ["captured_bytes"] = total, ["capture_complete"] = complete,
                ["retained_utf8_bytes"] = retained, ["retained_view_complete"] = complete && missing == 0,
                ["missing_lines"] = missing, ["decoding_loss"] = errors > 0,
                ["missing_decoded_line_ranges"] = new JsonArray(ranges.Select(r => (JsonNode)new JsonArray(r.Start, r.End)).ToArray()),
                ["decode_error_count"] = errors, ["redacted"] = redacted, ["raw_bytes_persisted"] = false,
                ["storage_error"] = storageError, ["output_reference"] = path is null ? null : Path.GetFileName(path),
                ["preview_head"] = head, ["preview_tail"] = tail, ["preview_complete"] = complete && total <= 512 && missing == 0
            };
    }

    public void Dispose() { lock (gate) { file?.Dispose(); file = null; } }

    private sealed class CountingFallback(Action count) : DecoderFallback
    {
        public override int MaxCharCount => 1;
        public override DecoderFallbackBuffer CreateFallbackBuffer() => new ReplacementBuffer(count);
        private sealed class ReplacementBuffer(Action count) : DecoderFallbackBuffer
        {
            private bool available;
            public override bool Fallback(byte[] bytesUnknown, int index) { count(); available = true; return true; }
            public override char GetNextChar() { if (!available) return '\0'; available = false; return '\ufffd'; }
            public override bool MovePrevious() { if (available) return false; available = true; return true; }
            public override int Remaining => available ? 1 : 0;
        }
    }
}

internal static class TextCodec
{
    internal static Encoding Get(string encoding)
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        if (encoding is "utf-16" or "utf-16-le") return new UnicodeEncoding(false, false, true);
        if (encoding == "utf-16-be") return new UnicodeEncoding(true, false, true);
        if (encoding == "utf-8-sig") return RecordJson.Utf8;
        return Encoding.GetEncoding(encoding, EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback);
    }
    internal static bool IsEnding(char c) => c is '\n' or '\r' or '\v' or '\f' or '\x1c' or '\x1d' or '\x1e' or '\x85' or '\u2028' or '\u2029';
    internal static IEnumerable<string> Lines(string text)
    {
        int start = 0;
        for (int i = 0; i < text.Length; i++)
            if (IsEnding(text[i]))
            {
                if (text[i] == '\r' && i + 1 < text.Length && text[i + 1] == '\n') i++;
                yield return text[start..(i + 1)];
                start = i + 1;
            }
        if (start < text.Length) yield return text[start..];
    }
}
