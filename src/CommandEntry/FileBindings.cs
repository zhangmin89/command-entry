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
