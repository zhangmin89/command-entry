"""Shared execution primitives for entry_v2: Job object, syntax precheck.

Retained from V1 as a library only. The V1 request/canonical/hook routes were
retired with the pure-beta stage-3 convergence and have been removed; nothing
here reads runtime.json or speaks to any hook protocol.
"""
import ctypes
from ctypes import wintypes
from pathlib import Path
import re
import subprocess
import threading

ROOT = Path(__file__).resolve().parent


class Invalid(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise Invalid(message)


def redact(text):
    text = re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)', '[REDACTED PRIVATE KEY]', text)
    text = re.sub(r'(?im)^.*(?:password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|secret|authorization|cookie)\s*[=:].*$', '[REDACTED credential line]', text)
    text = re.sub(r'(?i)\bBearer\s+\S+', 'Bearer [REDACTED]', text)
    text = re.sub(r'\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{16,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)', '[REDACTED]', text)
    return text


class Capture:
    def __init__(self, pipe, cap):
        self.pipe=pipe; self.cap=cap; self.data=bytearray(); self.total=0
        self.thread=threading.Thread(target=self.drain,daemon=True)
        self.thread.start()

    def drain(self):
        while True:
            chunk=self.pipe.read(8192)
            if not chunk: break
            self.total+=len(chunk)
            self.data.extend(chunk[:max(0,self.cap-len(self.data))])

    def result(self, encoding):
        self.thread.join(timeout=10)
        return {'text':redact(bytes(self.data).decode(encoding,errors='replace')),'bytes':self.total,'truncated':self.total>len(self.data),'capture_complete':not self.thread.is_alive()}


class Job:
    """Assign a waiting host before allowing it to create the actual task."""
    def __init__(self):
        self.api=ctypes.WinDLL('kernel32',use_last_error=True)
        self.api.CreateJobObjectW.argtypes=[ctypes.c_void_p,wintypes.LPCWSTR];self.api.CreateJobObjectW.restype=wintypes.HANDLE
        self.api.SetInformationJobObject.argtypes=[wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD]
        self.api.AssignProcessToJobObject.argtypes=[wintypes.HANDLE,wintypes.HANDLE]
        self.api.CloseHandle.argtypes=[wintypes.HANDLE]
        self.handle=self.api.CreateJobObjectW(None,None)
        if not self.handle: raise ctypes.WinError(ctypes.get_last_error())
        # JOBOBJECT_EXTENDED_LIMIT_INFORMATION, Windows x64 layout (144 bytes).
        require(ctypes.sizeof(ctypes.c_void_p)==8,'v1 requires Windows x64')
        info=ctypes.create_string_buffer(144)
        ctypes.c_uint32.from_buffer(info,16).value=0x2000 # KILL_ON_JOB_CLOSE
        if not self.api.SetInformationJobObject(self.handle,9,info,144):
            self.close();raise ctypes.WinError(ctypes.get_last_error())

    def assign(self,process):
        if not self.api.AssignProcessToJobObject(self.handle,int(process._handle)):
            raise ctypes.WinError(ctypes.get_last_error())

    def close(self):
        if self.handle:self.api.CloseHandle(self.handle);self.handle=None


def syntax(req):
    if req['mode']!='script':return {'status':'not_applicable'}
    lang=req['language'];exe=req['interpreter'];script=req['script']
    commands={'python':[exe,'-I','-X','utf8',str(ROOT/'check_python.py'),script],
              'powershell':[exe,'-NoProfile','-File',str(ROOT/'check_powershell.ps1'),'-ScriptPath',script],
              'javascript':[exe,'--check',script], 'bash':[exe,'-n',script]}
    p=subprocess.Popen(commands[lang],cwd=req['cwd'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=False,creationflags=subprocess.CREATE_NO_WINDOW)
    out=Capture(p.stdout,8192);err=Capture(p.stderr,8192)
    try:p.wait(timeout=10)
    except subprocess.TimeoutExpired:p.kill();p.wait(timeout=10)
    stdout=out.result('utf-8');stderr=err.result('utf-8')
    return {'status':'passed' if p.returncode==0 else 'failed','exit_code':p.returncode,'stdout':stdout,'stderr':stderr}
