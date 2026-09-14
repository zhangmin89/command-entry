"""Windows background launches keep console windows hidden and preserve I/O."""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import common
import entry_v2
import server
import v1_support
import worker_v2


PROBE = '''import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import sys
kernel = ctypes.WinDLL('kernel32', use_last_error=True)
user = ctypes.WinDLL('user32', use_last_error=True)
kernel.GetConsoleWindow.restype = wintypes.HWND
user.IsWindowVisible.argtypes = [wintypes.HWND]
user.IsWindowVisible.restype = wintypes.BOOL
window = kernel.GetConsoleWindow()
report = {'visible': bool(user.IsWindowVisible(window)),
          'stdin': sys.stdin.read(), 'cwd': str(Path.cwd())}
if len(sys.argv) > 1:
    Path(sys.argv[1]).write_text(json.dumps(report), encoding='utf-8')
else:
    print(json.dumps(report))
    print('probe-stderr', file=sys.stderr)
sys.exit(7)
'''


@unittest.skipUnless(os.name == 'nt', 'Windows console creation flags')
class NoWindowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='no-window-test '))
        self.script = self.tmp / 'probe.py'
        self.script.write_text(PROBE, encoding='utf-8')
        self.source = self.tmp / 'stdin.txt'
        self.source.write_text('input payload\n', encoding='utf-8')
        self.policy_path = self.tmp / 'policy.json'
        self.policy_path.write_text(json.dumps({
            'version': 2, 'python': sys.executable,
            'working_roots': [str(self.tmp)],
            'record_root': '.codex-command-records',
            'serve_root': str(self.tmp / 'serve'),
            'programs': {'python': {'kind': 'python', 'path': sys.executable}},
            'operations': {'script': {'acceptable_exit_codes': [0],
                                      'run_seconds': 20, 'wait_category': 'long_task'}},
            'output_quota_bytes': 65536, 'cleanup_seconds': 5,
            'cancel_grace_seconds': 15, 'require_orphan_guarantee': False,
        }), encoding='utf-8')

    def assert_no_window(self, call):
        flags = call.kwargs.get('creationflags', 0)
        self.assertEqual(flags & subprocess.CREATE_NO_WINDOW, subprocess.CREATE_NO_WINDOW)
        self.assertEqual(flags & (subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_CONSOLE), 0)
        self.assertIs(call.kwargs['shell'], False)

    def assert_report(self, report):
        self.assertIs(report['visible'], False, 'business process has a visible console window')
        self.assertEqual(report['stdin'], 'input payload\n')
        self.assertEqual(Path(report['cwd']), self.tmp)

    def assert_execution(self, result):
        self.assertEqual(result['state'], 'exited', result)
        self.assertEqual(result['process']['exit_code'], 7)
        self.assertIs(result['operation_result']['acceptable_exit'], False)
        directory = Path(result['record_dir'])
        self.assert_report(json.loads((directory / 'stdout.txt').read_text(encoding='utf-8')))
        self.assertEqual((directory / 'stderr.txt').read_text(encoding='utf-8'), 'probe-stderr\n')

    def test_entry_worker_launch_preserves_streams_and_exit_code(self):
        business = {'task_ref': 'no-window', 'step_ref': 'entry',
                    'operation': 'script', 'program': 'python', 'language': 'python',
                    'cwd': str(self.tmp), 'script': str(self.script),
                    'stdin_file': str(self.source)}
        request = self.tmp / 'request.json'
        common.write_new(request, {'business': business,
                                  'fingerprint': common.request_digest(common.shape(business))})
        with mock.patch.object(entry_v2.subprocess, 'Popen', wraps=subprocess.Popen) as spawn:
            result = entry_v2.run(request, self.policy_path)
        hosts = [call for call in spawn.call_args_list
                 if str(ROOT / 'worker_v2.py') in call.args[0]]
        self.assertEqual(len(hosts), 1)
        self.assert_no_window(hosts[0])
        self.assert_execution(result)

    def test_worker_launch_preserves_stdin_cwd_and_nonzero_exit(self):
        report_path = self.tmp / 'report.json'
        plan = {'handshake': 'job_assigned', 'cwd': str(self.tmp),
                'record_dir': str(self.tmp), 'stdin_file': str(self.source),
                'argv': [sys.executable, '-X', 'utf8', str(self.script), str(report_path)]}
        with io.TextIOWrapper(io.BytesIO(common.packed(plan) + b'\n'), encoding='utf-8') as incoming:
            with mock.patch.object(worker_v2.sys, 'stdin', incoming), \
                    mock.patch.object(worker_v2.subprocess, 'Popen', wraps=subprocess.Popen) as spawn:
                code = worker_v2.main()
        self.assertEqual(code, 7)
        spawn.assert_called_once()
        self.assert_no_window(spawn.call_args)
        self.assert_report(json.loads(report_path.read_text(encoding='utf-8')))
        self.assertGreater(common.read_json(self.tmp / 'business-process.json')['pid'], 0)

    def test_syntax_launch_keeps_valid_and_invalid_results(self):
        for name, code, expected in (('valid.py', 'x = 1\n', 'passed'),
                                     ('invalid.py', 'def broken(:\n', 'failed')):
            with self.subTest(name=name):
                script = self.tmp / name
                script.write_text(code, encoding='utf-8')
                with mock.patch.object(v1_support.subprocess, 'Popen', wraps=subprocess.Popen) as spawn:
                    result = v1_support.syntax({'mode': 'script', 'language': 'python',
                                                'interpreter': sys.executable,
                                                'script': str(script), 'cwd': str(self.tmp)})
                self.assertEqual(result['status'], expected)
                if expected == 'passed':
                    self.assertEqual(result['exit_code'], 0)
                else:
                    self.assertNotEqual(result['exit_code'], 0)
                    self.assertIn('SyntaxError', result['stderr']['text'])
                spawn.assert_called_once()
                self.assert_no_window(spawn.call_args)

    def test_detached_server_chain_has_no_visible_business_console(self):
        instance = server.Server(self.policy_path)
        started = instance.tool_start({'operation': 'script', 'program': 'python',
                                       'language': 'python', 'workdir': str(self.tmp),
                                       'script': str(self.script), 'stdin_file': str(self.source)})
        target = {'execution_id': started['execution_id']}
        result = instance.tool_status(target)
        try:
            deadline = time.monotonic() + 25
            while result['state'] not in server.TERMINAL and time.monotonic() < deadline:
                time.sleep(0.1)
                result = instance.tool_status(target)
            self.assert_execution(result)
        finally:
            if result['state'] not in server.TERMINAL:
                instance.tool_cancel(target)


if __name__ == '__main__':
    unittest.main(verbosity=2)
