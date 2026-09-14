using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using Microsoft.Win32.SafeHandles;

[assembly: System.Runtime.CompilerServices.DisableRuntimeMarshalling]

namespace CommandEntry;

internal static partial class WindowsProcess
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct BasicLimits
    {
        internal long PerProcessUserTime, PerJobUserTime;
        internal uint Flags;
        internal nuint MinimumWorkingSet, MaximumWorkingSet;
        internal uint ActiveProcessLimit;
        internal nuint Affinity;
        internal uint PriorityClass, SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ExtendedLimits
    {
        internal BasicLimits Basic;
        internal ulong ReadOperations, WriteOperations, OtherOperations;
        internal ulong ReadBytes, WriteBytes, OtherBytes;
        internal nuint ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemory, PeakJobMemory;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial SafeProcessHandle OpenProcess(uint access, int inherit, int pid);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial int GetProcessTimes(SafeProcessHandle handle, out ulong creation, out ulong exit, out ulong kernel, out ulong user);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial int GetExitCodeProcess(SafeProcessHandle handle, out uint code);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial int TerminateProcess(SafeProcessHandle handle, uint code);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial int IsProcessInJob(nint process, nint job, out int inside);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial int QueryInformationJobObject(nint job, int informationClass, out ExtendedLimits information, uint length, out uint written);
    [LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial SafeJobHandle CreateJobObjectW(nint attributes, string? name);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial int SetInformationJobObject(SafeJobHandle job, int informationClass, in ExtendedLimits information, uint length);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial int AssignProcessToJobObject(SafeJobHandle job, SafeProcessHandle process);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial int CloseHandle(nint handle);

    internal static double UnixNow => (DateTime.UtcNow.Ticks - DateTime.UnixEpoch.Ticks) / (double)TimeSpan.TicksPerSecond;

    internal static JsonObject Observe(int pid)
    {
        var result = new JsonObject
        {
            ["pid"] = pid, ["alive"] = null, ["creation_time"] = null,
            ["cpu_seconds"] = null, ["exit_code"] = null, ["observed_at_unix"] = UnixNow
        };
        using var handle = OpenProcess(0x1000, 0, pid);
        if (handle.IsInvalid)
        {
            if (Marshal.GetLastPInvokeError() == 87) result["alive"] = false;
            return result;
        }
        if (GetProcessTimes(handle, out ulong creation, out _, out ulong kernel, out ulong user) != 0)
        {
            result["creation_time"] = creation;
            result["cpu_seconds"] = (kernel + user) / 10000000.0;
        }
        if (GetExitCodeProcess(handle, out uint code) != 0)
        {
            result["alive"] = code == 259;
            if (code != 259) result["exit_code"] = code;
        }
        return result;
    }

    internal static JsonObject TerminateSameInstance(int? pid, ulong? creationTime)
    {
        if (pid is null || creationTime is null)
            return new() { ["terminated"] = false, ["reason"] = "instance_identity_missing" };
        using var handle = OpenProcess(0x1001, 0, pid.Value);
        if (handle.IsInvalid) return new() { ["terminated"] = false, ["reason"] = "open_failed" };
        if (GetProcessTimes(handle, out ulong actual, out _, out _, out _) == 0 || actual != creationTime)
            return new() { ["terminated"] = false, ["reason"] = "instance_mismatch" };
        return new() { ["terminated"] = TerminateProcess(handle, 1) != 0 };
    }

    internal static JsonObject JobEnvironment()
    {
        if (IsProcessInJob(-1, 0, out int inside) == 0)
            return new() { ["in_job"] = null, ["breakaway_allowed"] = null, ["probe_failed"] = true };
        if (inside == 0) return new() { ["in_job"] = false, ["breakaway_allowed"] = null };
        bool queried = QueryInformationJobObject(0, 9, out var limits, (uint)Marshal.SizeOf<ExtendedLimits>(), out _) != 0;
        return new() { ["in_job"] = true, ["breakaway_allowed"] = queried && (limits.Basic.Flags & 0x0800) != 0 };
    }

    internal static ProcessStartInfo StartInfo(string executable, IEnumerable<string> arguments, string workdir)
    {
        var info = new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            WorkingDirectory = workdir,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (string argument in arguments) info.ArgumentList.Add(argument);
        return info;
    }

    internal sealed class SafeJobHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeJobHandle() : base(ownsHandle: true) { }
        protected override bool ReleaseHandle() => CloseHandle(handle) != 0;
    }

    internal sealed class Job : IDisposable
    {
        private readonly SafeJobHandle handle;
        internal Job()
        {
            RecordJson.Require(Environment.Is64BitProcess && Marshal.SizeOf<ExtendedLimits>() == 144,
                "Windows_x64_required");
            handle = CreateJobObjectW(0, null);
            if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastPInvokeError());
            var limits = new ExtendedLimits { Basic = new BasicLimits { Flags = 0x2000 } };
            if (SetInformationJobObject(handle, 9, in limits, 144) == 0)
            {
                int error = Marshal.GetLastPInvokeError();
                handle.Dispose();
                throw new Win32Exception(error);
            }
        }
        internal void Assign(Process process)
        {
            if (AssignProcessToJobObject(handle, process.SafeHandle) == 0)
                throw new Win32Exception(Marshal.GetLastPInvokeError());
        }
        public void Dispose() => handle.Dispose();
    }
}
