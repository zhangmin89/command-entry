"""Candidate execution engine; always launched inside the original command tool."""
import argparse
import ast
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

from common import VERSION, Invalid, digest, load_policy, matches_request, packed, read_json, request_digest, require, save, shape, write_new
from output_store import Capture, redact_line
from v1_support import Job, syntax
from windows_state import FileLocks, observe
from wait_state import decide as decide_wait

ROOT = Path(__file__).resolve().parent
TERMINAL = {'exited','rejected','timed_out','cancelled','unknown','tool_error'}
SOURCE_FILES = ('entry_v2.py','common.py','worker_v2.py','windows_state.py','wait_state.py','adapter.py','output_store.py','v1_support.py','invoke.ps1','check_python.py','check_powershell.ps1')


def actual_location():
    cwd = Path.cwd().resolve()
    require(cwd != Path(cwd.anchor) and cwd != Path.home().resolve(), 'cwd cannot be a drive root or user home')
    return {'version':VERSION,'operation':'location','cwd':str(cwd), 'state':'exited',
            'process':{'exit_code':0,'exit_code_source':'fixed_location_operation'},
            'subgoal':{'status':'confirmed','evidence':'actual process cwd and unchanged root/home exclusions'},
            'persistence':{'durable':False,'result_readable_now':True,'cross_session_retrieval':False}}


def business_path(value, kind=None):
    path = Path(value).resolve(strict=kind is not None)
    require(path.is_absolute(), 'absolute_path_required')
    if kind == 'file':
        require(path.is_file(), 'input_file_missing')
    if kind == 'directory':
        require(path.is_dir(), 'working_directory_missing')
    return path


def context(policy, cwd):
    # This is a configured storage applicability check, never a sandbox override.
    require(any(cwd == Path(root).resolve() or cwd.is_relative_to(Path(root).resolve()) for root in policy['working_roots']), 'storage_context_not_configured_for_cwd')
    if policy['record_root'] == '.codex-command-records':
        return cwd / '.codex-command-records'
    return Path(policy['record_root']).resolve()


def execution_id(request_id):
    return str(uuid.uuid5(uuid.UUID(request_id), 'execution-instance'))


def snapshot(directory):
    file = directory/'result.json'
    if not file.is_file():
        return {'state':'unknown','reason':'claim_exists_without_readable_state','execution_id':directory.name}
    state = read_json(file)
    if state['state'] not in TERMINAL and state.get('owner'):
        current = observe(state['owner']['pid'])
        original = state['owner'].get('creation_time')
        if original is None or current.get('creation_time') != original or current['alive'] is not True:
            state.update(state='unknown', reason='owner_instance_not_confirmed')
        state['owner_observed_now'] = current
    return state


def bounded(result):
    # Detailed inputs/argv/bindings stay in the record; keep the control envelope small.
    view = {k:v for k,v in result.items() if k not in ('request','argv','bindings','syntax','progress_history')}
    if 'output' in view:
        view['output'] = {k:{a:b for a,b in v.items() if a not in ('preview_head','preview_tail')} for k,v in view['output'].items()}
    if len(packed(view)) > 12000:
        return {k:view.get(k) for k in ('version','execution_id','request_id','state','record_dir','process','persistence')}
    return view


def acceptance(req):
    evidence = []
    for condition in req.get('acceptance', []):
        path = business_path(req['artifacts'][condition['artifact']])
        item = {'condition':condition,'path':str(path),'matches':False}
        try:
            if condition['kind'] == 'exists':
                item['matches'] = path.is_file()
            elif condition['kind'] == 'sha256':
                item['matches'] = hashlib.sha256(path.read_bytes()).hexdigest() == condition['expected']
            else:
                obj = read_json(path)
                for key in condition.get('keys', []):
                    obj = obj[key]
                item['matches'] = obj == condition['expected']
        except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
            item['error'] = type(error).__name__
        evidence.append(item)
    return {'status':('confirmed' if all(e['matches'] for e in evidence) else 'not_fulfilled') if evidence else 'unknown','evidence':evidence}


def plan(req, policy, locks, directory):
    for name in ('input_paths','required_tools'):
        for value in req.get(name, []):
            path = business_path(value, 'file')
            locks.add(path)
    if 'stdin_file' in req:
        locks.add(business_path(req['stdin_file'], 'file'))
    op = req['operation']
    definition = policy.get('operations', {}).get(op)
    require(definition is not None and 'run_seconds' in definition, 'approved_run_budget_missing')
    budget = definition['run_seconds']
    require(type(budget) in (int,float) and 0 < budget <= 3600, 'invalid_approved_budget')
    program = policy.get('programs', {}).get(req.get('program'))
    require(program is not None, 'program_not_configured')
    executable = str(business_path(program['path'], 'file'))
    args = req.get('args', [])
    checked = {'status':'not_applicable'}
    if op == 'native':
        require(program['kind'] == 'native', 'interpreter_requires_explicit_script_or_module_operation')
        # V1 rule restored: native executables must be real .exe. Batch files
        # (.cmd/.bat) are routed through cmd.exe by CreateProcess, which
        # RE-INTERPRETS the argument line — model-controlled args containing
        # & | % ^ would escape the whitelist entirely (BatBadBut class).
        require(executable.lower().endswith('.exe'),
                'native_requires_exe_batch_files_route_through_cmd')
        argv = [executable,*args]
    elif op == 'python_unittest':
        require(program['kind'] == 'python', 'python_runtime_required')
        argv = [executable,'-X','utf8','-m','unittest',*args]
    else:
        lang = req['language']
        require(program['kind'] == lang, 'interpreter_language_mismatch')
        script = business_path(req['script'], 'file')
        locks.add(script)
        compatible = {'python':['.py'],'powershell':['.ps1'],'javascript':['.js','.mjs','.cjs','.ts',''],'bash':['.sh']}
        require(script.suffix.lower() in compatible[lang], 'script_form_not_supported')
        check_req = {'mode':'script','language':lang,'interpreter':executable,'script':str(script),'cwd':req['cwd']}
        if lang == 'powershell':
            require(not args, 'powershell_requires_parameters_file')
            if req.get('parameters_file'):
                locks.add(business_path(req['parameters_file'], 'file'))
                require(isinstance(read_json(req['parameters_file']), dict), 'parameter_object_required')
            invocation = dict(check_req)
            if req.get('parameters_file'):
                invocation['parameters_file'] = req['parameters_file']
            invoke_file = directory/'powershell-invocation.json'
            write_new(invoke_file, invocation)
            locks.add(invoke_file)
            argv = [executable,'-NoProfile','-File',str(ROOT/'invoke.ps1'),'-RequestPath',str(invoke_file)]
        else:
            require('parameters_file' not in req, 'parameters_file_only_for_powershell')
            argv = [executable,*(['-X','utf8'] if lang == 'python' else []),str(script),*args]
        checked = syntax(check_req)
        require(checked['status'] == 'passed', 'script_syntax_check_failed: ' + checked.get('stderr', {}).get('text', '')[:500])
    for path, expected in req.get('expected_versions', {}).items():
        locks.add(business_path(path, 'file'))
        require(locks.bindings[str(Path(path).resolve())] == expected, 'declared_content_version_changed')
    return argv, budget, checked


def fixed_text(req, store=None):
    path = business_path(req['file'], 'file')
    capture = Capture(None, req.get('encoding','utf-8'), quota=0)
    start, count = req.get('start_line',1), req.get('line_count',100)
    with path.open('rb') as source:
        for index, line in enumerate(source, 1):
            if index >= start + count:
                break
            if index >= start:
                capture.feed(line)
    capture.feed(b'', final=True)
    return {'version':VERSION,'state':'exited','operation':'read_text','file':str(path),
            'process':{'exit_code':0,'exit_code_source':'fixed_text_read'},'subgoal':{'status':'unknown'},
            'output':capture.metadata(), 'persistence':{'durable':False,'result_readable_now':True,'cross_session_retrieval':False}}


def run(request_path, policy_path):
    started = time.monotonic()
    with FileLocks() as locks:
        locks.add(request_path)
        envelope = read_json(request_path)
        req = shape(envelope['business'])
        require(matches_request(envelope['fingerprint'], req), 'prepared_request_content_conflict')
        if req['operation'] == 'location':
            return actual_location()
        cwd = business_path(req['cwd'], 'directory')
        require(cwd != Path(cwd.anchor) and cwd != Path.home().resolve(), 'cwd cannot be a drive root or user home')
        locks.add(policy_path)
        policy = load_policy(policy_path)
        base = context(policy, cwd)
        if req['operation'] == 'read_text':
            return fixed_text(req)
        if req['operation'] in ('status','output','cancel'):
            binding = envelope.get('query_binding')
            require(isinstance(binding,dict) and binding['query_request_id'] == req['request_id'] and binding['execution_id'] == req['execution_id'], 'query_target_binding_required')
            origin_path = Path(policy['prepare_root'])/(binding['request_id']+'.json')
            locks.add(origin_path)
            origin = shape(read_json(origin_path)['business'])
            require(execution_id(origin['request_id']) == req['execution_id'] and request_digest(origin) == binding['request_fingerprint'], 'query_origin_content_conflict')
            directory = base/req['execution_id']
            result = snapshot(directory)
            require(result.get('cwd') == str(cwd), 'record_cwd_context_mismatch')
            require(result.get('request_id') == binding['request_id'] and matches_request(result.get('request_fingerprint'),origin), 'query_record_identity_conflict')
            if 'wait_receipt' in req:
                receipt_path = Path(policy['prepare_root'])/req['wait_receipt']
                locks.add(receipt_path)
                return decide_wait(directory,result,req,read_json(receipt_path),policy)
            if req['operation'] == 'cancel':
                if result['state'] not in TERMINAL:
                    try:
                        write_new(directory/'cancel-request.json', {'requested_at':time.time(),'request_id':req['request_id']})
                    except FileExistsError:
                        pass
                    result['cancel_request'] = 'recorded_not_yet_confirmed'
            if req['operation'] == 'output':
                stream = req.get('stream','stdout')
                output_path = directory/(stream+'.txt')
                require(output_path.is_file(), 'retained_output_unavailable')
                text = output_path.read_text(encoding='utf-8')
                offset, count = req.get('offset',0), req.get('count',2048)
                return {'execution_id':directory.name,'query_request_id':req['request_id'],'target_request_id':result['request_id'],'state':result['state'],'stream':stream,'offset_characters':offset,
                        'text':text[offset:offset+count], 'next_offset':min(offset+count,len(text)),
                        'retained_view_end':offset+count >= len(text), 'metadata':result.get('output',{}).get(stream),
                        'business_restarted':False}
            return dict(bounded(result),query_request_id=req['request_id'],target_request_id=result['request_id'])
        identity = execution_id(req['request_id'])
        directory = base/identity
        base.mkdir(parents=True, exist_ok=True)
        try:
            directory.mkdir()
        except FileExistsError:
            old = snapshot(directory)
            if old.get('reason') == 'claim_exists_without_readable_state':
                return dict(old, request_id=req['request_id'], duplicate_delivery=True)
            require(matches_request(old.get('request_fingerprint'), req), 'request_identity_content_conflict')
            for path, old_hash in old.get('bindings', {}).items():
                if path in (str(Path(request_path).resolve()), str(Path(policy_path).resolve())) or path.endswith('powershell-invocation.json'):
                    continue
                require(Path(path).is_file() and hashlib.sha256(Path(path).read_bytes()).hexdigest() == old_hash, 'bound_file_changed_for_existing_identity')
            old['duplicate_delivery'] = True
            return bounded(old)
        result = {'version':VERSION,'execution_id':identity,'request_id':req['request_id'],'logical_id':req['logical_id'],
                  'request_fingerprint':request_digest(req),'state':'not_started','cwd':str(cwd),'record_dir':str(directory),
                  'request':req,'owner':observe(os.getpid()),'process':{'exit_code':None,'exit_code_source':None},
                  'subgoal':{'status':'unknown'},'persistence':{'durable':True,'result_readable_now':True,'cross_session_retrieval':True},
                  'started_at_unix':time.time(),'last_observed_unix':time.time()}
        result['source_fingerprint'] = digest({name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in SOURCE_FILES})
        result['input_observations'] = {str(Path(p).resolve()):{'exists':Path(p).is_file()} for p in req.get('input_paths',[])+req.get('required_tools',[])}
        save(directory/'result.json', result)
        job = host = None
        capture = {}
        guard = threading.Lock()
        done = threading.Event()
        timer = monitor = None
        def persist():
            result['last_observed_unix'] = time.time()
            result['elapsed_seconds'] = time.monotonic()-started
            result['output'] = {name:cap.metadata() for name,cap in capture.items()}
            save(directory/'result.json', result)
        def end_task(reason):
            with guard:
                if done.is_set():
                    return
                result['stop_reason'] = reason
                result['state'] = 'cleaning'
                try:
                    persist()
                finally:
                    if job:
                        job.close()
        def observe_progress():
            while not done.wait(10):
                if (directory/'cancel-request.json').is_file():
                    end_task('cancelled')
                    return
                with guard:
                    result['owner_observation'] = observe(os.getpid())
                    if (directory/'business-process.json').is_file():
                        birth = read_json(directory/'business-process.json')
                        current = observe(birth['pid'])
                        current['same_instance'] = birth['creation_time'] is not None and birth['creation_time'] == current['creation_time']
                        result['business_observation'] = current
                    result['artifact_observations'] = {name:({'size':Path(path).stat().st_size,'mtime_ns':Path(path).stat().st_mtime_ns} if Path(path).is_file() else None) for name,path in req.get('artifacts',{}).items()}
                    try:
                        persist()
                    except OSError:
                        result['state'] = 'unknown'
                        result['reason'] = 'mandatory_state_write_failed'
                        if job:
                            job.close()
                        return
        try:
            argv, budget, checked = plan(req, policy, locks, directory)
            result.update(argv=argv, bindings=dict(locks.bindings), syntax=checked, run_budget_seconds=budget)
            if req['attempt']:
                old = snapshot(base/execution_id(req['previous_request']))
                require(old.get('logical_id') == req['logical_id'] and old['state'] in ('rejected','exited','timed_out','cancelled'), 'previous_attempt_not_confirmed_terminal')
                comparable = {p:h for p,h in locks.bindings.items() if p in old.get('bindings',{}) and p not in (str(Path(request_path).resolve()),str(Path(policy_path).resolve()))}
                changed = [p for p,h in comparable.items() if h != old['bindings'][p]]
                require(changed, 'verified_changed_conditions_required_for_new_attempt')
                require(old['request'].get('acceptance',[]) == req.get('acceptance',[]) and old['request'].get('artifacts',{}) == req.get('artifacts',{}), 'original_acceptance_must_be_preserved')
                result['changed_conditions'] = changed
            result['state'] = 'starting'
            persist()
            job = Job()
            host = subprocess.Popen([sys.executable,'-X','utf8',str(ROOT/'worker_v2.py')],cwd=cwd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=False)
            job.assign(host)
            for name in ('stdout','stderr'):
                capture[name] = Capture(directory/(name+'.txt'), req.get('encoding','utf-8'), policy['output_quota_bytes'])
                capture[name].start(getattr(host,name))
            result.update(state='running', worker=observe(host.pid))
            persist()
            host.stdin.write(packed({'handshake':'job_assigned','argv':argv,'cwd':str(cwd),'record_dir':str(directory),'stdin_file':req.get('stdin_file')})+b'\n')
            host.stdin.flush()
            host.stdin.close()
            timer = threading.Timer(budget, end_task, args=('timed_out',))
            timer.daemon = True
            timer.start()
            monitor = threading.Thread(target=observe_progress,daemon=True)
            monitor.start()
            host.wait()  # Overall lifetime is bounded by timer/Job, not the caller's wait window.
            done.set()
            timer.cancel()
            job.close()
            for cap in capture.values():
                cap.thread.join(timeout=policy['cleanup_seconds'])
            result['state'] = result.get('stop_reason','exited')
            result['process'] = {'exit_code':host.returncode,'exit_code_source':'terminated_worker' if result.get('stop_reason') else 'worker_propagated_business_process','worker_pid':host.pid}
            if (directory/'business-process.json').is_file():
                result['business_start'] = read_json(directory/'business-process.json')
                result['business_observation'] = observe(result['business_start']['pid'])
            else:
                result.update(state='unknown',reason='business_start_record_missing')
                result['process']['exit_code_source'] = 'worker_without_confirmed_business_start'
            result['worker_observation'] = observe(host.pid)
            definition = policy['operations'][req['operation']]
            result['operation_result'] = {'acceptable_exit':host.returncode in definition.get('acceptable_exit_codes',[0]) if result['state'] == 'exited' else None}
            result['subgoal'] = acceptance(req) if result['state'] == 'exited' else {'status':'unknown'}
        except (Invalid,OSError,ValueError,KeyError,TypeError) as error:
            result['state'] = 'rejected' if host is None else 'tool_error'
            result['error'] = {'kind':type(error).__name__,'reason':redact_line(str(error))[:600]}
            result['bindings'] = dict(locks.bindings)
            if job:
                job.close()
            if host:
                host.wait(timeout=policy['cleanup_seconds'])
                result['process']['exit_code'] = host.returncode
        finally:
            done.set()
            if timer:
                timer.cancel()
            if job:
                job.close()
            if monitor:
                monitor.join(timeout=policy['cleanup_seconds'])
        persist()
        return bounded(result)


def serve(record_dir):
    """Spawned by the exec server: execute from a prepared input directory.

    record_dir holds request.json and policy.json written by the server before
    spawning. Execution records still follow V2 semantics: the policy-defined
    record root under the business cwd. Nothing is printed because stdout may
    not exist in a detached process; failures outside run() land in
    serve-error.json inside record_dir.
    """
    directory = Path(record_dir)
    try:
        result = run(str(directory/'request.json'), str(directory/'policy.json'))
        return 0 if result.get('state') in ('exited','running','starting','cancel_requested','cleaning') else 125
    except (Invalid,OSError,ValueError,KeyError,TypeError) as error:
        write_new(directory/'serve-error.json', {'version':VERSION,'state':'not_started','execution_id':None,
                   'subgoal':{'status':'unknown'},
                   'error':{'kind':type(error).__name__,'reason':redact_line(str(error))[:600]}})
        return 125


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('location','run','serve'))
    parser.add_argument('--request')
    parser.add_argument('--policy')
    parser.add_argument('--record-dir')
    opts = parser.parse_args()
    if opts.action == 'serve':
        require(opts.record_dir is not None, '--record-dir required')
        return serve(opts.record_dir)
    try:
        result = actual_location() if opts.action == 'location' else run(opts.request, opts.policy)
    except (Invalid,OSError,ValueError,KeyError,TypeError) as error:
        result = {'version':VERSION,'state':'not_started','execution_id':None,'subgoal':{'status':'unknown'},'error':{'kind':type(error).__name__,'reason':redact_line(str(error))[:600]}}
    print(json.dumps(result,ensure_ascii=True))
    return 0 if result.get('state') in ('exited','running','starting','cancel_requested','cleaning') else 125


if __name__ == '__main__':
    sys.exit(main())
