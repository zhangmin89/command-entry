using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using Microsoft.Win32.SafeHandles;
using static CommandEntry.RecordJson;

namespace CommandEntry;

internal static partial class BusinessPaths
{
    [LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial SafeFileHandle CreateFileW(string path, uint access, uint sharing, nint security, uint disposition, uint flags, nint template);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial uint GetFinalPathNameByHandleW(SafeFileHandle handle, [Out] char[] path, uint length, uint flags);

    internal static string Resolve(string value, string? kind = null)
    {
        string path = Path.GetFullPath(value);
        using var handle = CreateFileW(path, 0, 7, 0, 3, 0x02000000, 0);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastPInvokeError();
            if (kind is null && error is 2 or 3)
            {
                string? parent = Path.GetDirectoryName(path);
                Require(parent is not null && parent != path, "absolute_path_required");
                return Path.Combine(Resolve(parent!), Path.GetFileName(path));
            }
            throw new Win32Exception(error);
        }
        path = FromHandle(handle);
        if (kind == "file") Require(File.Exists(path), "input_file_missing");
        if (kind == "directory") Require(Directory.Exists(path), "working_directory_missing");
        return path;
    }

    internal static string FromHandle(SafeFileHandle handle)
    {
        char[] buffer = new char[32768];
        uint length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Length, 0);
        if (length == 0) throw new Win32Exception(Marshal.GetLastPInvokeError());
        Require(length < buffer.Length, "resolved_path_too_long");
        string path = new(buffer, 0, (int)length);
        if (path.StartsWith("\\\\?\\UNC\\", StringComparison.OrdinalIgnoreCase)) path = "\\\\" + path[8..];
        else if (path.StartsWith("\\\\?\\", StringComparison.Ordinal)) path = path[4..];
        return Path.TrimEndingDirectorySeparator(path);
    }

    internal static bool Within(string path, string root) =>
        string.Equals(path, root, StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith(Path.TrimEndingDirectorySeparator(root) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);

    internal static bool SameArtifacts(JsonObject before, JsonObject after) => before.Count == after.Count
        && before.All(pair => after.ContainsKey(pair.Key)
            && Resolve(pair.Value.String()).Equals(Resolve(after[pair.Key].String()), StringComparison.OrdinalIgnoreCase));

    internal static string Context(JsonObject policy, string cwd)
    {
        Require(policy["working_roots"].Array().Any(root => Within(cwd, Resolve(root.String()))), "storage_context_not_configured_for_cwd");
        string record = policy["record_root"].String();
        return record == ".codex-command-records" ? Path.Combine(cwd, record) : Resolve(record);
    }

    internal static void CheckCwd(string cwd)
    {
        Require(!string.Equals(cwd, Path.GetPathRoot(cwd), StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(cwd, Resolve(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)), StringComparison.OrdinalIgnoreCase),
            "cwd cannot be a drive root or user home");
    }
}
