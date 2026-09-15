using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace CommandEntry;

internal sealed class InvalidRequest(string reason) : Exception(reason);

internal static class RecordJson
{
    internal const string Version = "2.0.0-candidate.3-closeout.2";
    private static readonly Guid IdentityNamespace = new("a93e3e64-c90b-4ca6-a8da-bcf070c04196");
    internal static readonly UTF8Encoding Utf8 = new(false, true);

    internal static void Require(bool condition, string reason)
    {
        if (!condition) throw new InvalidRequest(reason);
    }

    internal static JsonObject Read(string path) =>
        JsonNode.Parse(File.ReadAllText(path, Utf8))?.AsObject()
        ?? throw new InvalidRequest("request_object_required");

    // Record identities must agree with Python's ensure_ascii=True canonical JSON.
    // Writing JsonNode directly avoids reflection and preserves AOT compatibility.
    internal static byte[] Packed(JsonNode? value)
    {
        var text = new StringBuilder();
        Append(value, text);
        return Utf8.GetBytes(text.ToString());
    }

    internal static string Digest(JsonNode? value) => Hash(Packed(value));
    internal static string Hash(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexStringLower(SHA256.HashData(bytes));

    internal static string FileHash(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }

    internal static string RequestDigest(JsonObject request)
    {
        var content = (JsonObject)request.DeepClone();
        content.Remove("version");
        return Digest(content);
    }

    internal static bool MatchesRequest(string? fingerprint, JsonObject request)
    {
        if (fingerprint == RequestDigest(request)) return true;
        foreach (var label in new[] { "2.0.0-candidate.1", "2.0.0-candidate.2" })
        {
            var legacy = (JsonObject)request.DeepClone();
            legacy["version"] = label;
            if (fingerprint == Digest(legacy)) return true;
        }
        return false;
    }

    internal static string RequestId(string task, string step, long attempt) =>
        Uuid5(IdentityNamespace, Utf8.GetString(Packed(new JsonArray(task, step, attempt))));
    internal static string LogicalId(string task, string step) =>
        Uuid5(IdentityNamespace, Utf8.GetString(Packed(new JsonArray(task, step))));
    internal static string ExecutionId(string requestId) => Uuid5(Guid.Parse(requestId), "execution-instance");

    private static string Uuid5(Guid scope, string name)
    {
        byte[] nameBytes = Utf8.GetBytes(name);
        byte[] input = new byte[16 + nameBytes.Length];
        scope.TryWriteBytes(input, bigEndian: true, out _);
        nameBytes.CopyTo(input, 16);
        Span<byte> hash = stackalloc byte[20];
        SHA1.HashData(input, hash); // UUID v5, not an integrity hash.
        hash[6] = (byte)((hash[6] & 0x0f) | 0x50);
        hash[8] = (byte)((hash[8] & 0x3f) | 0x80);
        return new Guid(hash[..16], bigEndian: true).ToString();
    }

    internal static void WriteNew(string path, JsonNode value)
    {
        using var target = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        target.Write(Packed(value));
        target.Flush(flushToDisk: true);
    }

    internal static void PublishNew(string path, JsonNode value)
    {
        string temporary = path + "." + Guid.NewGuid() + ".pending";
        WriteNew(temporary, value);
        try { File.Move(temporary, path, overwrite: false); }
        finally
        {
            // Only this invocation's unpublished scratch file, never a record.
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    internal static void Save(string path, JsonNode value)
    {
        string temporary = path + "." + Guid.NewGuid() + ".tmp";
        WriteNew(temporary, value);
        for (int attempt = 0; ; attempt++)
        {
            try { File.Move(temporary, path, overwrite: true); return; }
            catch (IOException error) when (attempt < 4 && (error.HResult & 0xffff) is 5 or 32)
            { Thread.Sleep(20); }
            catch (UnauthorizedAccessException) when (attempt < 4)
            { Thread.Sleep(20); }
        }
    }

    private static void Append(JsonNode? node, StringBuilder text)
    {
        switch (node)
        {
            case null: text.Append("null"); break;
            case JsonObject obj:
                text.Append('{');
                bool first = true;
                foreach (var pair in obj.OrderBy(p => p.Key, ScalarComparer.Instance))
                {
                    if (!first) text.Append(',');
                    first = false;
                    AppendString(pair.Key, text);
                    text.Append(':');
                    Append(pair.Value, text);
                }
                text.Append('}');
                break;
            case JsonArray array:
                text.Append('[');
                for (int i = 0; i < array.Count; i++)
                {
                    if (i != 0) text.Append(',');
                    Append(array[i], text);
                }
                text.Append(']');
                break;
            case JsonValue value:
                switch (value.GetValueKind())
                {
                    case JsonValueKind.String: AppendString(value.GetValue<string>(), text); break;
                    case JsonValueKind.True: text.Append("true"); break;
                    case JsonValueKind.False: text.Append("false"); break;
                    case JsonValueKind.Number:
                        text.Append(Number(value.ToJsonString(), !value.TryGetValue<JsonElement>(out _) && value.TryGetValue<double>(out _)));
                        break;
                    default: throw new InvalidRequest("unsupported_json_value");
                }
                break;
        }
    }

    private static string Number(string raw, bool createdDouble = false)
    {
        if (!createdDouble && raw.IndexOfAny(['.', 'e', 'E']) < 0)
            return BigInteger.Parse(raw, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture);
        double number = double.Parse(raw, CultureInfo.InvariantCulture);
        string shortest = number.ToString("R", CultureInfo.InvariantCulture).ToLowerInvariant();
        int exponentAt = shortest.IndexOf('e');
        if (exponentAt >= 0)
        {
            int exponent = int.Parse(shortest[(exponentAt + 1)..], CultureInfo.InvariantCulture);
            if (exponent >= -4 && exponent < 16)
                return number.ToString("0.0###############", CultureInfo.InvariantCulture);
            return shortest[..exponentAt] + "e" + (exponent < 0 ? "-" : "+")
                + Math.Abs(exponent).ToString("D2", CultureInfo.InvariantCulture);
        }
        if (Math.Abs(number) >= 1e16)
        {
            // Reformat the round-trip digits without a second numeric conversion:
            // custom numeric formats can round away significant double digits.
            string sign = shortest.StartsWith('-') ? "-" : "";
            string digits = shortest[sign.Length..];
            string significant = digits.TrimEnd('0');
            return sign + significant[..1] + (significant.Length > 1 ? "." + significant[1..] : "")
                + "e+" + (digits.Length - 1).ToString("D2", CultureInfo.InvariantCulture);
        }
        return shortest.Contains('.') ? shortest : shortest + ".0";
    }

    private static void AppendString(string value, StringBuilder text)
    {
        text.Append('"');
        foreach (char c in value)
            switch (c)
            {
                case '"': text.Append("\\\""); break;
                case '\\': text.Append("\\\\"); break;
                case '\b': text.Append("\\b"); break;
                case '\f': text.Append("\\f"); break;
                case '\n': text.Append("\\n"); break;
                case '\r': text.Append("\\r"); break;
                case '\t': text.Append("\\t"); break;
                default:
                    if (c < 32 || c > 126) text.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else text.Append(c);
                    break;
            }
        text.Append('"');
    }

    private sealed class ScalarComparer : IComparer<string>
    {
        internal static readonly ScalarComparer Instance = new();
        public int Compare(string? x, string? y)
        {
            if (x is null || y is null) return string.CompareOrdinal(x, y);
            var left = x.EnumerateRunes().GetEnumerator();
            var right = y.EnumerateRunes().GetEnumerator();
            while (left.MoveNext())
            {
                if (!right.MoveNext()) return 1;
                int difference = left.Current.Value.CompareTo(right.Current.Value);
                if (difference != 0) return difference;
            }
            return right.MoveNext() ? -1 : 0;
        }
    }
}
