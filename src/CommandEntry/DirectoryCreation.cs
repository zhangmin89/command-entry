using System.ComponentModel;
using System.Runtime.InteropServices;

namespace CommandEntry;

internal static partial class DirectoryCreation
{
    [LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial int CreateDirectoryW(string path, nint attributes);
    internal static bool TryCreateNew(string path)
    {
        if (CreateDirectoryW(path, 0) != 0) return true;
        int error = Marshal.GetLastPInvokeError();
        if (error == 183) return false;
        throw new Win32Exception(error);
    }
}
