using System.Collections;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace CommandEntry;

internal static partial class OwnerLauncher
{
    internal const string InputVariable = "COMMAND_ENTRY_OWNER_INPUT";

    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfo
    {
        internal uint Size;
        internal nint Reserved, Desktop, Title;
        internal uint X, Y, XSize, YSize, XCount, YCount, Fill, Flags;
        internal ushort ShowWindow, ReservedLength;
        internal nint ReservedBytes, Stdin, Stdout, Stderr;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        internal nint Process, Thread;
        internal uint ProcessId, ThreadId;
    }
    [LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial int CreateProcessW(string application, [In, Out] char[] commandLine,
        nint processAttributes, nint threadAttributes, int inheritHandles, uint flags,
        [In] char[] environment, string directory, in StartupInfo startup, out ProcessInformation process);

    internal static (uint Flags, bool Guaranteed) Flags()
    {
        var environment = WindowsProcess.JobEnvironment();
        if (environment["probe_failed"].IsTrue()) return (8, false);
        if (environment["in_job"].IsTrue())
            return environment["breakaway_allowed"].IsTrue() ? (8u | 0x01000000u, true) : (8u, false);
        return (8, true);
    }

    internal static int Start(string inputDirectory, string cwd, uint flags)
    {
        string executable = Path.Combine(AppContext.BaseDirectory, "CommandEntry.exe");
        RecordJson.Require(File.Exists(executable), "owner_executable_missing");
        // Native creation flags are unavailable on ProcessStartInfo. Only the
        // fixed owner executable crosses this boundary; business argv never does.
        // Pass the input reference in the child environment, not a command string.
        var environment = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (DictionaryEntry pair in Environment.GetEnvironmentVariables())
            environment.Add((string)pair.Key, (string)pair.Value!);
        environment[InputVariable] = inputDirectory;
        char[] block = (string.Concat(environment.Select(pair => pair.Key + "=" + pair.Value + '\0')) + '\0').ToCharArray();
        char[] command = ('"' + executable + "\"\0").ToCharArray();
        var startup = new StartupInfo { Size = (uint)Marshal.SizeOf<StartupInfo>(), Flags = 1, ShowWindow = 0 };
        if (CreateProcessW(executable, command, 0, 0, 0, flags | 0x400, block, cwd, in startup, out var info) == 0)
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        using var process = new SafeProcessHandle(info.Process, ownsHandle: true);
        using var thread = new SafeFileHandle(info.Thread, ownsHandle: true);
        return checked((int)info.ProcessId);
    }
}
