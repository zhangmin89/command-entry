"""Stage 1 regression: the untouched V2 paths still behave identically.

The stdin_file restoration touched shape(), plan() and the worker handshake;
this suite proves the pre-existing operations (location, read_text, native,
script without stdin) are unchanged end to end.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import common  # noqa: E402
import entry_v2  # noqa: E402


class V2RegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix='v2-regression '))
        cls.policy_path = cls.tmp / 'policy.json'
        cls.policy_path.write_text(json.dumps({
            'version': 2,
            'candidate_entry': str(ROOT / 'entry_v2.py'),
            'python': sys.executable,
            'working_roots': [str(cls.tmp)],
            'record_root': '.codex-command-records',
            'programs': {'python': {'kind': 'python', 'path': sys.executable},
                         'git': {'kind': 'native', 'path': r'C:\Program Files\Git\cmd\git.exe'}},
            'operations': {
                'native': {'acceptable_exit_codes': [0], 'run_seconds': 60,
                           'wait_category': 'long_task'},
                'script': {'acceptable_exit_codes': [0], 'run_seconds': 60,
                           'wait_category': 'long_task'}},
            'output_quota_bytes': 65536,
            'cleanup_seconds': 10,
        }), encoding='utf-8')

    def write_envelope(self, business):
        req = common.shape(business)
        envelope = {'schema_version': 2, 'business': business,
                    'fingerprint': common.request_digest(req)}
        target = self.tmp / (req['request_id'] + '.json')
        target.write_text(json.dumps(envelope), encoding='utf-8')
        return target

    def execute(self, business):
        return entry_v2.run(str(self.write_envelope(business)), str(self.policy_path))

    def test_native_without_stdin_still_executes(self):
        result = self.execute({'task_ref': 'regression', 'step_ref': 'native',
                               'operation': 'native', 'cwd': str(self.tmp),
                               'program': 'git', 'args': ['--version']})
        self.assertEqual(result['state'], 'exited', result.get('error'))
        self.assertEqual(result['process']['exit_code'], 0)

    def test_native_interpreter_smuggling_still_rejected(self):
        result = self.execute({'task_ref': 'regression', 'step_ref': 'smuggle',
                               'operation': 'native', 'cwd': str(self.tmp),
                               'program': 'python', 'args': ['-c', 'pass']})
        self.assertEqual(result['state'], 'rejected')
        self.assertIn('interpreter_requires_explicit_script_or_module_operation',
                      result['error']['reason'])

    def test_script_without_stdin_still_executes(self):
        script = self.tmp / 'print.py'
        script.write_text('print("ok")\n', encoding='utf-8')
        result = self.execute({'task_ref': 'regression', 'step_ref': 'script',
                               'operation': 'script', 'cwd': str(self.tmp),
                               'program': 'python', 'language': 'python',
                               'script': str(script)})
        self.assertEqual(result['state'], 'exited', result.get('error'))
        retained = (Path(result['record_dir']) / 'stdout.txt').read_text(encoding='utf-8')
        self.assertIn('ok', retained)

    def test_read_text_still_works(self):
        target = self.tmp / 'sample.txt'
        target.write_text('line-a\nline-b\nline-c\n', encoding='utf-8')
        result = self.execute({'task_ref': 'regression', 'step_ref': 'read',
                               'operation': 'read_text', 'cwd': str(self.tmp),
                               'file': str(target), 'start_line': 2, 'line_count': 1})
        self.assertEqual(result['state'], 'exited')
        self.assertIn('line-b', result['output']['preview_head'])

    def test_duplicate_delivery_still_returns_existing(self):
        business = {'task_ref': 'regression', 'step_ref': 'dup',
                   'operation': 'native', 'cwd': str(self.tmp),
                   'program': 'git', 'args': ['--version']}
        first = self.execute(business)
        second = self.execute(business)
        self.assertEqual(first['state'], 'exited')
        self.assertTrue(second.get('duplicate_delivery'))
        self.assertEqual(second['execution_id'], first['execution_id'])

    def test_location_reports_cwd(self):
        result = entry_v2.actual_location()
        self.assertEqual(result['operation'], 'location')
        self.assertNotEqual(Path(result['cwd']), Path.home())


if __name__ == '__main__':
    unittest.main(verbosity=2)
