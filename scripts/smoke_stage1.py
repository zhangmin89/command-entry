"""Stage 1 smoke test: breakaway feasibility + entry `serve` mode.

Verifies plan 0.1's physical prerequisite before any server work:
1. Reports the current process Job environment (IsProcessInJob + breakaway-ok).
2. Runs three spawn scenarios; each scenario process joins a controlled Job
   (none / breakaway-allowed / breakaway-forbidden), spawns a detached
   `entry_v2.py serve` child exactly the way the exec server will, waits for
   the terminal record, and reports PASS/FAIL as one JSON line.

Usage: python scripts/smoke_stage1.py [--scenario NAME]
"""
import argparse
import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import common  # noqa: E402
from windows_state import job_environment, spawn_creation_flags  # noqa: E402

GIT = r'C:\Program Files\Git\cmd\git.exe'
SCENARIOS = ('no_job', 'breakaway_ok', 'no_breakaway')


def join_self_job(allow_breakaway):
    """Put this process into a fresh Job so spawn flags can be exercised."""
    api = ctypes.WinDLL('kernel32', use_last_error=True)
    api.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    api.CreateJobObjectW.restype = wintypes.HANDLE
    api.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    api.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    handle = api.CreateJobObjectW(None, None)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    info = ctypes.create_string_buffer(144)
    ctypes.c_uint32.from_buffer(info, 16).value = 0x0800 if allow_breakaway else 0
    if not api.SetInformationJobObject(handle, 9, info, 144):
        raise ctypes.WinError(ctypes.get_last_error())
    if not api.AssignProcessToJobObject(handle, ctypes.c_void_p(-1)):
        raise ctypes.WinError(ctypes.get_last_error())
    return handle


def build_record(root, name):
    """Prepare one serve input directory the way the exec server will."""
    directory = root / ('smoke-' + name + '-' + str(int(time.time() * 1000)))
    directory.mkdir(parents=True)
    policy = {
        'version': 2,
        'candidate_entry': str(ROOT / 'entry_v2.py'),
        'python': sys.executable,
        'working_roots': [str(root)],
        'record_root': '.codex-command-records',
        'programs': {'git': {'kind': 'native', 'path': GIT}},
        'operations': {'native': {'acceptable_exit_codes': [0], 'run_seconds': 60,
                                  'wait_category': 'long_task'}},
        'output_quota_bytes': 65536,
        'cleanup_seconds': 10,
    }
    (directory / 'policy.json').write_text(json.dumps(policy), encoding='utf-8')
    business = {'task_ref': 'smoke-stage1', 'step_ref': directory.name,
                'operation': 'native', 'cwd': str(root), 'program': 'git',
                'args': ['--version']}
    req = common.shape(business)
    envelope = {'schema_version': 2, 'business': business,
                'fingerprint': common.request_digest(req)}
    (directory / 'request.json').write_text(json.dumps(envelope), encoding='utf-8')
    return directory, req


def execution_dir(root, req):
    """Where run() persists: <cwd>/.codex-command-records/<execution_id>."""
    return root / '.codex-command-records' / entry_execution_id(req['request_id'])


def entry_execution_id(request_id):
    import uuid
    return str(uuid.uuid5(uuid.UUID(request_id), 'execution-instance'))


def wait_terminal(directory, timeout=60):
    result_path = directory / 'result.json'
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if result_path.is_file():
            state = json.loads(result_path.read_text(encoding='utf-8')).get('state')
            if state in ('exited', 'rejected', 'timed_out', 'cancelled', 'unknown', 'tool_error'):
                return state
        time.sleep(0.2)
    return 'wait_timeout'


def run_scenario(name):
    root = Path(tempfile.mkdtemp(prefix='smoke-stage1-' + name + ' '))
    job = None
    if name == 'breakaway_ok':
        job = join_self_job(allow_breakaway=True)
    elif name == 'no_breakaway':
        job = join_self_job(allow_breakaway=False)
    environment = job_environment()
    flags, orphan_guaranteed = spawn_creation_flags()
    directory, req = build_record(root, name)
    report = {'scenario': name, 'environment': environment,
              'flags': hex(flags), 'orphan_guaranteed': orphan_guaranteed}
    try:
        child = subprocess.Popen(
            [sys.executable, '-X', 'utf8', str(ROOT / 'entry_v2.py'), 'serve',
             '--record-dir', str(directory)],
            creationflags=flags, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, cwd=str(root), shell=False)
    except OSError as error:
        # The spawn itself failed: environment finding, not a crash. Which
        # scenario failed tells whether breakaway is available here.
        report.update({'spawn_error': type(error).__name__, 'winerror': getattr(error, 'winerror', None),
                       'pass': False})
        print(json.dumps(report, ensure_ascii=True))
        return report
    report['child_pid'] = child.pid
    try:
        code = child.wait(timeout=60)
        report['child_exit_code'] = code
    except subprocess.TimeoutExpired:
        child.kill()
        report['child_exit_code'] = 'timeout'
    report['terminal_state'] = wait_terminal(execution_dir(root, req))
    result = json.loads((execution_dir(root, req) / 'result.json').read_text(encoding='utf-8'))
    report['business_exit_code'] = result.get('process', {}).get('exit_code')
    report['subgoal'] = result.get('subgoal', {}).get('status')
    report['pass'] = (report['child_exit_code'] == 0 and
                      report['terminal_state'] == 'exited' and
                      report['business_exit_code'] == 0)
    if job:
        ctypes.WinDLL('kernel32').CloseHandle(job)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--scenario', choices=SCENARIOS)
    options = parser.parse_args()
    if options.scenario:
        print(json.dumps(run_scenario(options.scenario), ensure_ascii=True))
        return 0
    print(json.dumps({'environment': job_environment()}, ensure_ascii=True))
    failures = []
    for name in SCENARIOS:
        report = json.loads(subprocess.run(
            [sys.executable, '-X', 'utf8', str(Path(__file__).resolve()), '--scenario', name],
            capture_output=True, text=True, encoding='utf-8', timeout=180).stdout.strip())
        print(json.dumps(report, ensure_ascii=True))
        if not report['pass']:
            failures.append(name)
    print(json.dumps({'summary': 'PASS' if not failures else 'FAIL',
                      'failed': failures}, ensure_ascii=True))
    return 0 if not failures else 1


if __name__ == '__main__':
    sys.exit(main())
