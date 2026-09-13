"""Codex command entry v1. No daemon, shell rewriting, approval or retries."""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parent
VERSION = '1.0.0'


class Invalid(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise Invalid(message)


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def save(path, obj):
    # Only execution-specific files are replaced; operation claims use exclusive creation.
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(obj, ensure_ascii=True, indent=2), encoding='utf-8')
    os.replace(temp, path)


def redact(text):
    text = re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)', '[REDACTED PRIVATE KEY]', text)
    text = re.sub(r'(?im)^.*(?:password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|secret|authorization|cookie)\s*[=:].*$', '[REDACTED credential line]', text)
    text = re.sub(r'(?i)\bBearer\s+\S+', 'Bearer [REDACTED]', text)
    text = re.sub(r'\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{16,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)', '[REDACTED]', text)
    return text


def path_value(value, label, kind=None):
    require(isinstance(value, str) and bool(value) and '\0' not in value, label + ' must be a path string')
    p = Path(value)
    require(p.is_absolute(), label + ' must be absolute')
    p = p.resolve()
    if kind == 'file': require(p.is_file(), label + ' file missing')
    if kind == 'dir': require(p.is_dir(), label + ' directory missing')
    return p


def validate(req):
    require(isinstance(req, dict), 'request must be an object')
    known = {'version','request_id','mode','cwd','executable','args','language','interpreter','script','parameters_file','command','parameters','required_tools','input_paths','stdin_file','timeout_seconds','max_output_bytes','encoding','acceptance'}
    require(not (set(req) - known), 'unknown request fields')
    require(req.get('version') == 1, 'version must be 1')
    require(isinstance(req.get('request_id'), str), 'request_id must be UUID')
    require(str(uuid.UUID(req['request_id'])) == req['request_id'], 'request_id must be canonical UUID')
    cwd = path_value(req.get('cwd'), 'cwd', 'dir')
    require(cwd != Path(cwd.anchor) and cwd != Path.home().resolve(), 'cwd cannot be a drive root or user home')
    args = req.get('args', [])
    require(isinstance(args,list) and all(isinstance(x,str) and '\0' not in x for x in args), 'args must be separate strings')
    for field in ['required_tools','input_paths']:
        values = req.get(field, [])
        require(isinstance(values,list), field + ' must be an array')
        for value in values:
            p = path_value(value, field, 'file' if field == 'required_tools' else None)
            require(p.exists(), field + ' path missing')
    if 'stdin_file' in req: path_value(req['stdin_file'], 'stdin_file', 'file')
    timeout = req.get('timeout_seconds',60)
    require(type(timeout) in [int,float] and 0 < timeout <= 3600, 'timeout_seconds must be in (0,3600]')
    cap = req.get('max_output_bytes',65536)
    require(type(cap) is int and 256 <= cap <= 1048576, 'max_output_bytes must be 256..1048576 per stream')
    require(req.get('encoding','utf-8') in ['utf-8','gbk','utf-16-le'], 'unsupported output encoding')
    mode = req.get('mode')
    if mode == 'native':
        exe = path_value(req.get('executable'), 'executable', 'file')
        require(exe.suffix.lower() == '.exe', 'native mode requires .exe; use script mode for scripts')
        # Interpreter entrypoints must not smuggle unchecked inline code or script paths.
        if re.match(r'(?i)^(python|pythonw|py|node|pwsh|powershell|cmd|bash|sh|wscript|cscript)([0-9.]*)$', exe.stem):
            require(args in [['--version'],['-V'],['/?']], 'interpreter execution requires script or cmdlet mode')
        command = [str(exe), *args]
    elif mode == 'script':
        exe = path_value(req.get('interpreter'), 'interpreter', 'file')
        script = path_value(req.get('script'), 'script', 'file')
        lang = req.get('language')
        require(lang in ['python','powershell','javascript','bash'], 'unsupported language; no Bash translation')
        matches = {'python':r'python(?:[0-9.]*)','powershell':r'pwsh','javascript':r'node','bash':r'bash'}
        require(re.fullmatch(matches[lang],exe.stem,re.I) is not None, 'interpreter does not match language')
        require(script.suffix.lower() in {'python':['.py'],'powershell':['.ps1'],'javascript':['.js','.mjs','.cjs'],'bash':['.sh']}[lang], 'script extension mismatch')
        if lang == 'powershell':
            require(not args, 'PowerShell uses parameters_file JSON, not argv arrays')
            if 'parameters_file' in req:
                params = read_json(path_value(req['parameters_file'],'parameters_file','file'))
                require(isinstance(params,dict), 'parameters_file must contain an object')
            command = [str(exe),'-NoProfile','-File',str(ROOT/'invoke.ps1'),'-RequestPath','{REQUEST}']
        else:
            require('parameters_file' not in req, 'parameters_file only supported for PowerShell')
            command = [str(exe), *(['-X','utf8'] if lang == 'python' else []),str(script),*args]
    elif mode == 'cmdlet':
        exe = path_value(req.get('interpreter'), 'interpreter','file')
        require(exe.stem.lower()=='pwsh', 'cmdlet mode requires PowerShell 7')
        require(isinstance(req.get('command'),str) and re.fullmatch(r'[A-Za-z]+-[A-Za-z]+',req['command']), 'command must be a cmdlet name')
        require(isinstance(req.get('parameters',{}),dict), 'parameters must be an object')
        require(not args, 'cmdlet mode uses parameters object')
        command = [str(exe),'-NoProfile','-File',str(ROOT/'invoke.ps1'),'-RequestPath','{REQUEST}']
    else:
        raise Invalid('mode must be native, script or cmdlet')
    acceptance = req.get('acceptance',[])
    require(isinstance(acceptance,list), 'acceptance must be a list')
    for a in acceptance:
        require(isinstance(a,dict) and set(a)=={'path','sha256'}, 'acceptance requires path and sha256')
        path_value(a['path'],'acceptance path')
        require(isinstance(a['sha256'],str) and re.fullmatch('[a-f0-9]{64}',a['sha256']), 'acceptance sha256 invalid')
    return cwd,command


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
    p=subprocess.Popen(commands[lang],cwd=req['cwd'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=False)
    out=Capture(p.stdout,8192);err=Capture(p.stderr,8192)
    try:p.wait(timeout=10)
    except subprocess.TimeoutExpired:p.kill();p.wait(timeout=10)
    stdout=out.result('utf-8');stderr=err.result('utf-8')
    return {'status':'passed' if p.returncode==0 else 'failed','exit_code':p.returncode,'stdout':stdout,'stderr':stderr}


def worker(request_path, record_dir):
    # No task starts until the parent has successfully assigned this host to its job.
    require(sys.stdin.buffer.readline()==b'GO\n','missing parent handshake')
    raw=Path(request_path).read_bytes()
    req=json.loads(raw.decode('utf-8-sig'));cwd,command=validate(req)
    command=[request_path if x=='{REQUEST}' else x for x in command]
    incoming=open(req['stdin_file'],'rb') if 'stdin_file' in req else subprocess.DEVNULL
    try:
        proc=subprocess.Popen(command,cwd=cwd,stdin=incoming,shell=False)
        save(Path(record_dir)/'process.json',{'host_pid':os.getpid(),'task_pid':proc.pid})
        proc.wait()
        return proc.returncode
    finally:
        if incoming!=subprocess.DEVNULL:incoming.close()


def run(request_path):
    started=time.perf_counter();execution_id=str(uuid.uuid4())
    # Invalid request results are returned without attempting to write into an unvalidated cwd.
    try:
        req=read_json(request_path)
        cwd=path_value(req.get('cwd'), 'cwd','dir')
        require(cwd != Path(cwd.anchor) and cwd != Path.home().resolve(), 'cwd cannot be a drive root or user home')
    except (ValueError,OSError,TypeError,AttributeError) as e:
        return {'execution_id':execution_id,'process':{'status':'preflight_rejected','exit_code':None},'subgoal':{'status':'unknown'},'error':redact(str(e)),'record_dir':None},125
    base=cwd/'.codex-command-records';directory=base/execution_id
    directory.mkdir(parents=True,exist_ok=False)
    result={'version':VERSION,'execution_id':execution_id,'record_dir':str(directory),'cwd':str(cwd),'started_at_unix':time.time(),'process':{'status':'not_started','exit_code':None},'subgoal':{'status':'unknown','evidence':[]},'retry_count':0}
    try:
        cwd,command=validate(req)
    except (ValueError,OSError,KeyError,TypeError) as e:
        result['process']['status']='preflight_rejected';result['error']=redact(str(e));result['elapsed_seconds']=time.perf_counter()-started
        save(directory/'result.json',result)
        return result,125
    result.update({'request_id':req['request_id'],'mode':req['mode'],'executable':command[0]})
    result['request_sha256']=hashlib.sha256(Path(request_path).read_bytes()).hexdigest()
    save(directory/'result.json',result)
    claims=base/'claims';claims.mkdir(exist_ok=True)
    try:
        with (claims/(req['request_id']+'.json')).open('x',encoding='utf-8') as f:json.dump({'execution_id':execution_id},f)
    except FileExistsError:
        result['process']['status']='duplicate_request_rejected'
        result['elapsed_seconds']=time.perf_counter()-started
        save(directory/'result.json',result)
        return result,125
    checked=syntax(req);result['syntax']=checked
    if checked['status']=='failed':
        result['process']['status']='syntax_rejected';result['elapsed_seconds']=time.perf_counter()-started
        save(directory/'result.json',result)
        return result,125
    job=None;host=None
    try:
        job=Job()
        host=subprocess.Popen([sys.executable,'-I','-X','utf8',str(ROOT/'entry.py'),'worker','--request',str(request_path),'--record-dir',str(directory)],cwd=cwd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=False)
        job.assign(host)
        result['process'].update({'status':'running','host_pid':host.pid})
        save(directory/'result.json',result)
        out=Capture(host.stdout,req.get('max_output_bytes',65536));err=Capture(host.stderr,req.get('max_output_bytes',65536))
        host.stdin.write(b'GO\n');host.stdin.flush();host.stdin.close()
        try:
            host.wait(timeout=req.get('timeout_seconds',60));state='exited'
        except subprocess.TimeoutExpired:
            state='timed_out';job.close();host.wait(timeout=10)
        except KeyboardInterrupt:
            state='cancelled';job.close();host.wait(timeout=10)
        job.close()
        result['stdout']=out.result(req.get('encoding','utf-8'));result['stderr']=err.result(req.get('encoding','utf-8'))
        result['process'].update({'status':state,'exit_code':host.returncode})
        if (directory/'process.json').exists():result['process'].update(read_json(directory/'process.json'))
        if req.get('acceptance') and state=='exited':
            evidence=[]
            for a in req['acceptance']:
                p=Path(a['path']);actual=hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
                evidence.append({'path':str(p),'sha256':actual,'matches':actual==a['sha256']})
            result['subgoal']={'status':'confirmed' if all(a['matches'] for a in evidence) else 'not_fulfilled','evidence':evidence,'scope':'Only the declared file content hashes; no broader success claim'}
    except OSError as e:
        if job:job.close()
        if host and host.poll() is None:host.kill();host.wait(timeout=10)
        result['process']['status']='launch_error'
        result['error']={'type':type(e).__name__,'winerror':getattr(e,'winerror',None),'message':redact(str(e))}
    finally:
        if job:job.close()
    result['elapsed_seconds']=time.perf_counter()-started
    # stdout is returned to Codex, not collected in persistent logs. Errors are redacted/capped.
    stored=json.loads(json.dumps(result))
    if 'stdout' in stored:stored['stdout'].pop('text');stored['stdout']['text_persisted']=False
    if 'stderr' in stored:
        stored['stderr']['text']=stored['stderr']['text'][:2048]
        stored['stderr']['persistent_preview_limit']=2048
    save(directory/'result.json',stored)
    state=result['process']['status']
    code=result['process']['exit_code'] if state=='exited' else (124 if state=='timed_out' else 125)
    return result,code


def canonical(request_path):
    settings=read_json(ROOT/'runtime.json')
    path=str(Path(request_path).resolve())
    require(re.fullmatch(r'[A-Za-z0-9_ .\\:/\-\u0080-\uffff]+',path) is not None,'request filename contains shell metacharacters; choose a UUID filename')
    return f'{settings["python"]} -I -X utf8 {ROOT / "entry.py"} run --request "{path}"'


def hook():
    event=json.load(sys.stdin)
    if event.get('hook_event_name')!='PreToolUse' or event.get('tool_name')!='Bash':return {}
    command=event.get('tool_input',{}).get('command')
    reason='Use Codex command entry: create a version-1 request JSON in the workspace, then run the canonical entry.py command through the original Codex command tool with explicit PowerShell 7 and login=false. See '+str(ROOT/'README.md')+'. This hook never executes the task or approves permissions.'
    try:
        require(isinstance(command,str),'command missing')
        settings=read_json(ROOT/'runtime.json')
        if command==f'{settings["python"]} -I -X utf8 {ROOT / "entry.py"} location':return {}
        marker=' run --request "'
        require(marker in command and command.endswith('"'),'noncanonical command')
        request_path=command.split(marker,1)[1][:-1]
        require(command==canonical(request_path),'noncanonical command')
        validate(read_json(request_path))
        return {} # Decline to approve; original Codex approval/sandbox flow continues.
    except (ValueError,OSError,KeyError,TypeError) as e:
        return {'hookSpecificOutput':{'hookEventName':'PreToolUse','permissionDecision':'deny','permissionDecisionReason':reason+' Check: '+redact(str(e))[:300]}}


def hook_main():
    # Observe only the minimal envelope; never retain the command, request, environment or output.
    started=time.perf_counter()
    raw=sys.stdin.read()
    import io
    sys.stdin=io.StringIO(raw)
    try:
        event=json.loads(raw);answer=hook()
    except (ValueError,OSError,KeyError,TypeError) as e:
        event={};answer={'hookSpecificOutput':{'hookEventName':'PreToolUse','permissionDecision':'deny','permissionDecisionReason':'Command entry hook could not validate the call: '+redact(str(e))[:200]}}
    meta={'id':str(uuid.uuid4()),'session_id':event.get('session_id'),'tool_use_id':event.get('tool_use_id'),'tool_name':event.get('tool_name'),'decision':'deny' if answer else 'defer_to_codex','elapsed_seconds':time.perf_counter()-started,'timestamp':time.time()}
    logs=ROOT/'hook-records';logs.mkdir(exist_ok=True)
    with (logs/(meta['id']+'.json')).open('x',encoding='utf-8') as f:json.dump(meta,f)
    print(json.dumps(answer,ensure_ascii=True))


def location():
    cwd=Path.cwd().resolve()
    require(cwd!=Path(cwd.anchor) and cwd!=Path.home().resolve(),'cwd cannot be a drive root or user home')
    identity=str(uuid.uuid4());directory=cwd/'.codex-command-records'/identity
    directory.mkdir(parents=True,exist_ok=False)
    result={'execution_id':identity,'cwd':str(cwd),'process':{'status':'exited','exit_code':0},'subgoal':{'status':'confirmed','evidence':'Current process working directory read and root/home exclusions checked'},'operation':'location','record_dir':str(directory)}
    save(directory/'result.json',result)
    print(json.dumps(result,ensure_ascii=True))


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('action',choices=['run','worker','hook','command','check','location'])
    parser.add_argument('--request');parser.add_argument('--record-dir')
    opts=parser.parse_args()
    if opts.action=='hook':hook_main();return 0
    if opts.action=='location':location();return 0
    require(opts.request is not None,'--request required')
    if opts.action=='worker':return worker(opts.request,opts.record_dir)
    if opts.action=='command':print(canonical(opts.request));return 0
    if opts.action=='check':
        req=read_json(opts.request);validate(req);print(json.dumps(syntax(req),ensure_ascii=True));return 0
    result,code=run(opts.request);print(json.dumps(result,ensure_ascii=True));return code


if __name__=='__main__':
    try:sys.exit(main())
    except (Invalid,ValueError,OSError,KeyError,TypeError) as e:
        print(json.dumps({'process':{'status':'preflight_rejected','exit_code':None},'subgoal':{'status':'unknown'},'error':redact(str(e))},ensure_ascii=True))
        sys.exit(125)
