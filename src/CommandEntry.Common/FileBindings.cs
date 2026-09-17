using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace CommandEntry;

internal sealed class FileBindings : IDisposable
{
    private readonly List<FileStream> handles = [];
    internal JsonObject Bindings { get; } = new();

    internal void Add(string path)
    {
        path = BusinessPaths.Resolve(path, "file");
        if (Bindings.ContainsKey(path)) return;
        var handle = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        handles.Add(handle);
        Bindings[path] = Convert.ToHexStringLower(SHA256.HashData(handle));
    }

    internal JsonObject ReadPublication(string path, string? expectedHash, string role)
    {
        var handle = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        handles.Add(handle);
        string resolved = BusinessPaths.FromHandle(handle.SafeFileHandle);
        string hash = Convert.ToHexStringLower(SHA256.HashData(handle));
        RecordJson.Require(expectedHash is null || hash == expectedHash, "publication_" + role + "_changed");
        Bindings[resolved] = hash;
        handle.Position = 0;
        using var reader = new StreamReader(handle, RecordJson.Utf8, detectEncodingFromByteOrderMarks: true, leaveOpen: true);
        return JsonNode.Parse(reader.ReadToEnd()).Object();
    }

    public void Dispose()
    {
        foreach (var handle in handles) handle.Dispose();
        handles.Clear();
    }
}

internal sealed class FileMutex(string path) : IDisposable
{
    private readonly FileStream handle = new(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
    public void Dispose() => handle.Dispose();
}
