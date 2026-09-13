"""Process-instance observations and deny-write/delete file handles on Windows."""
import ctypes
from ctypes import wintypes
import hashlib
from pathlib import Path
import time

K = ctypes.WinDLL('kernel32', use_last_error=True)
K.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
K.OpenProcess.restype = wintypes.HANDLE
K.CloseHandle.argtypes = [wintypes.HANDLE]
K.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)]*4
K.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
K.CreateFileW.argtypes = [wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
K.CreateFileW.restype = wintypes.HANDLE
K.IsProcessInJob.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
K.QueryInformationJobObject.argtypes = [wintypes.HANDLE, wintypes.INT, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
K.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]

JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x0800
DETACHED_PROCESS = 0x00000008
CREATE_BREAKAWAY_FROM_JOB = 0x01000000


def number(ft):
    return (ft.dwHighDateTime << 32) | ft.dwLowDateTime


def observe(pid):
    result = {'pid':pid, 'alive':None, 'creation_time':None, 'cpu_seconds':None, 'exit_code':None, 'observed_at_unix':time.time()}
    h = K.OpenProcess(0x1000, False, pid)
    if not h:
        if ctypes.get_last_error() == 87:
            result['alive'] = False
        return result
    try:
        times = [wintypes.FILETIME() for _ in range(4)]
        if K.GetProcessTimes(h, *[ctypes.byref(t) for t in times]):
            result['creation_time'] = number(times[0])
            result['cpu_seconds'] = (number(times[2])+number(times[3]))/10000000
        code = wintypes.DWORD()
        if K.GetExitCodeProcess(h, ctypes.byref(code)):
            result['alive'] = code.value == 259
            if code.value != 259:
                result['exit_code'] = code.value
        return result
    finally:
        K.CloseHandle(h)


def job_environment():
    """Observe whether this process runs inside a Job and breakaway is allowed.

    Probe only: no Job handles are created or modified here. in_job=None means
    the query itself failed; breakaway_allowed is only meaningful when in_job.
    """
    inside = wintypes.BOOL()
    if not K.IsProcessInJob(ctypes.c_void_p(-1), None, ctypes.byref(inside)):
        return {'in_job': None, 'breakaway_allowed': None, 'probe_failed': True}
    if not inside.value:
        return {'in_job': False, 'breakaway_allowed': None}
    info = ctypes.create_string_buffer(144)
    written = wintypes.DWORD()
    ok = K.QueryInformationJobObject(None, 9, info, ctypes.sizeof(info), ctypes.byref(written))
    flags = ctypes.c_uint32.from_buffer(info, 16).value if ok else None
    return {'in_job': True, 'breakaway_allowed': flags is not None and bool(flags & JOB_OBJECT_LIMIT_BREAKAWAY_OK)}


def spawn_creation_flags():
    """Choose creation flags so an entry child can outlive this process's Job.

    Returns (flags, orphan_guaranteed) per the beta plan 0.1: outside any Job no
    breakaway flag is needed; inside a breakaway-allowed Job the flag escapes
    it; inside a forbidding Job we spawn without the flag and report
    orphan_guaranteed=False so callers can fail closed via policy
    (require_orphan_guarantee) instead of silently losing the guarantee.
    """
    environment = job_environment()
    if environment.get('probe_failed'):
        return DETACHED_PROCESS, False
    if environment.get('in_job') and environment.get('breakaway_allowed'):
        return DETACHED_PROCESS | CREATE_BREAKAWAY_FROM_JOB, True
    if environment.get('in_job'):
        return DETACHED_PROCESS, False
    return DETACHED_PROCESS, True


def terminate_if_same_instance(pid, creation_time):
    """Terminate a process only when it is still the observed instance.

    The PID plus creation-time check prevents killing an unrelated process
    after PID reuse. Returns a report; never raises for a failed open.
    """
    if not isinstance(pid, int) or creation_time is None:
        return {'terminated': False, 'reason': 'instance_identity_missing'}
    handle = K.OpenProcess(0x1001, False, pid)  # QUERY_LIMITED_INFORMATION | TERMINATE
    if not handle:
        return {'terminated': False, 'reason': 'open_failed'}
    try:
        times = [wintypes.FILETIME() for _ in range(4)]
        if not K.GetProcessTimes(handle, *[ctypes.byref(t) for t in times]) or number(times[0]) != creation_time:
            return {'terminated': False, 'reason': 'instance_mismatch'}
        return {'terminated': bool(K.TerminateProcess(handle, 1))}
    finally:
        K.CloseHandle(handle)


class FileLocks:
    def __init__(self):
        self.handles = []
        self.bindings = {}

    def add(self, path):
        path = Path(path).resolve(strict=True)
        if str(path) in self.bindings:
            return
        h = K.CreateFileW(str(path), 0x80000000, 1, None, 3, 0x80, None)
        if h == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        self.handles.append(h)
        self.bindings[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()

    def close(self):
        for handle in self.handles:
            K.CloseHandle(handle)
        self.handles.clear()

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()


class FileMutex:
    """A process-scoped, exclusive metadata lock. No permission changes or retry loop."""
    def __init__(self, path):
        self.path = Path(path)

    def __enter__(self):
        self.handle = K.CreateFileW(str(self.path), 0xC0000000, 0, None, 4, 0x80, None)
        if self.handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        return self

    def __exit__(self, *unused):
        K.CloseHandle(self.handle)
