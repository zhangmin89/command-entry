"""Stage 1 stdin_file regression: content actually reaches the child process.

Covers the plan's restored capability: shape validation, FileLocks content
binding, handshake passthrough, and the retry rule (bound-file modification
counts as a verified change; adding a new unbound file does not).
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


class StdinFileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix='stdin-file-test '))
        cls.policy_path = cls.tmp / 'policy.json'
        cls.policy_path.write_text(json.dumps({
            'version': 2,
            'candidate_entry': str(ROOT / 'entry_v2.py'),
            'python': sys.executable,
            'working_roots': [str(cls.tmp)],
            'record_root': '.codex-command-records',
            'programs': {'python': {'kind': 'python', 'path': sys.executable}},
            'operations': {'script': {'acceptable_exit_codes': [0], 'run_seconds': 60,
                                      'wait_category': 'long_task'}},
            'output_quota_bytes': 65536,
            'cleanup_seconds': 10,
        }), encoding='utf-8')
        # A python script that copies its stdin to the file named by argv[1].
        cls.relay = cls.tmp / 'relay.py'
        cls.relay.write_text(
            'import sys\n'
            'from pathlib import Path\n'
            'Path(sys.argv[1]).write_bytes(sys.stdin.buffer.read())\n',
            encoding='utf-8')

    def write_request(self, business):
        req = common.shape(business)
        envelope = {'schema_version': 2, 'business': business,
                    'fingerprint': common.request_digest(req)}
        target = self.tmp / (req['request_id'] + '.json')
        target.write_text(json.dumps(envelope), encoding='utf-8')
        return target, req

    def execute(self, business):
        target, req = self.write_request(business)
        result = entry_v2.run(str(target), str(self.policy_path))
        return result, req

    def test_stdin_content_reaches_child(self):
        source = self.tmp / 'input-first.txt'
        source.write_bytes('stdin 中文 payload\nsecond line\n'.encode('utf-8'))
        output = self.tmp / 'out-first.txt'
        result, _ = self.execute({
            'task_ref': 'stdin-case', 'step_ref': 'first', 'operation': 'script',
            'cwd': str(self.tmp), 'program': 'python', 'language': 'python',
            'script': str(self.relay), 'args': [str(output)],
            'stdin_file': str(source), 'artifacts': {'out': str(output)},
            'acceptance': [{'artifact': 'out', 'kind': 'exists'}],
        })
        self.assertEqual(result['state'], 'exited', result.get('error'))
        self.assertEqual(result['subgoal']['status'], 'confirmed')
        self.assertEqual(output.read_bytes(), source.read_bytes())
        stored = common.read_json(Path(result['record_dir']) / 'result.json')
        self.assertIn(str(Path(source).resolve()), stored['bindings'])

    def test_stdin_modification_is_verified_change_for_retry(self):
        source = self.tmp / 'input-retry.txt'
        source.write_bytes(b'attempt-one')
        output = self.tmp / 'out-retry.txt'
        first, first_req = self.execute({
            'task_ref': 'stdin-case', 'step_ref': 'retry', 'operation': 'script',
            'cwd': str(self.tmp), 'program': 'python', 'language': 'python',
            'script': str(self.relay), 'args': [str(output)],
            'stdin_file': str(source), 'artifacts': {'out': str(output)},
            'acceptance': [{'artifact': 'out', 'kind': 'exists'}],
        })
        self.assertEqual(first['state'], 'exited', first.get('error'))
        source.write_bytes(b'attempt-two-after-edit')
        second, _ = self.execute({
            'task_ref': 'stdin-case', 'step_ref': 'retry', 'attempt': 1,
            'previous_request': first_req['request_id'], 'operation': 'script',
            'cwd': str(self.tmp), 'program': 'python', 'language': 'python',
            'script': str(self.relay), 'args': [str(output)],
            'stdin_file': str(source), 'artifacts': {'out': str(output)},
            'acceptance': [{'artifact': 'out', 'kind': 'exists'}],
        })
        self.assertEqual(second['state'], 'exited', second.get('error'))
        self.assertIn(str(Path(source).resolve()), second.get('changed_conditions', []))
        self.assertEqual(output.read_bytes(), b'attempt-two-after-edit')

    def test_new_unbound_file_alone_is_not_verified_change(self):
        source = self.tmp / 'input-novel.txt'
        source.write_bytes(b'unchanged')
        output = self.tmp / 'out-novel.txt'
        first, first_req = self.execute({
            'task_ref': 'stdin-case', 'step_ref': 'novel', 'operation': 'script',
            'cwd': str(self.tmp), 'program': 'python', 'language': 'python',
            'script': str(self.relay), 'args': [str(output)],
            'stdin_file': str(source), 'artifacts': {'out': str(output)},
            'acceptance': [{'artifact': 'out', 'kind': 'exists'}],
        })
        self.assertEqual(first['state'], 'exited', first.get('error'))
        # Same bound inputs, only a previously unbound file is added: the
        # verified-changed rule must refuse a new attempt.
        target, _ = self.write_request({
            'task_ref': 'stdin-case', 'step_ref': 'novel', 'attempt': 1,
            'previous_request': first_req['request_id'], 'operation': 'script',
            'cwd': str(self.tmp), 'program': 'python', 'language': 'python',
            'script': str(self.relay), 'args': [str(output)],
            'stdin_file': str(source), 'input_paths': [str(self.tmp / 'extra.txt')],
            'artifacts': {'out': str(output)},
            'acceptance': [{'artifact': 'out', 'kind': 'exists'}],
        })
        (self.tmp / 'extra.txt').write_bytes(b'new file')
        result = entry_v2.run(str(target), str(self.policy_path))
        self.assertEqual(result['state'], 'rejected')
        self.assertIn('verified_changed_conditions_required', result['error']['reason'])

    def test_stdin_rejected_for_read_only_operation(self):
        with self.assertRaises(Exception) as caught:
            common.shape({'task_ref': 'stdin-case', 'step_ref': 'bad',
                          'operation': 'read_text', 'cwd': str(self.tmp),
                          'file': str(self.relay), 'stdin_file': str(self.relay)})
        self.assertIn('stdin_file_requires_execution_operation', str(caught.exception))

    def test_stdin_missing_file_rejected(self):
        result, _ = self.execute({
            'task_ref': 'stdin-case', 'step_ref': 'missing', 'operation': 'script',
            'cwd': str(self.tmp), 'program': 'python', 'language': 'python',
            'script': str(self.relay), 'args': [str(self.tmp / 'out-missing.txt')],
            'stdin_file': str(self.tmp / 'does-not-exist.txt'),
        })
        self.assertEqual(result['state'], 'rejected')
        self.assertEqual(result['error']['kind'], 'FileNotFoundError')


if __name__ == '__main__':
    unittest.main(verbosity=2)
