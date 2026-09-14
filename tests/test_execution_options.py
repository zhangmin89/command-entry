"""Per-call execution resources: bounded overrides, identity and real output."""
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import common
import entry_v2
import server
from scripts.validate_policy import validate
from tests.test_review_fixes import make_policy


class ExecutionOptionsFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='execution-options '))
        self.policy, self.policy_path = make_policy(self.tmp)
        self.policy['powershell'] = sys.executable
        self.policy['read_quota_bytes'] = 65536
        self.policy['output_quota_bytes'] = 1048576
        for operation in ('native', 'script', 'python_unittest'):
            self.policy['operations'][operation] = {
                'run_seconds': 300, 'acceptable_exit_codes': [0],
                'wait_category': 'long_task'}
        common.save(self.policy_path, self.policy)
        self.server = server.Server(self.policy_path)
        self.form = {'operation': 'native', 'program': 'git',
                     'workdir': str(self.tmp), 'args': ['--version']}

    def hold_start(self, command, **kwargs):
        serve_dir = Path(command[command.index('--record-dir') + 1])
        record = self.tmp / '.codex-command-records' / serve_dir.name
        record.mkdir(parents=True)
        common.write_new(record / 'result.json', {'state': 'running',
                                                 'execution_id': serve_dir.name})
        return object()

    def prepare(self, **options):
        with mock.patch.object(server.subprocess, 'Popen', self.hold_start):
            started = self.server.tool_start(dict(self.form, **options))
        envelope = common.read_json(self.server.serve_root / started['execution_id'] / 'request.json')
        return started, envelope['business']


class ExecutionOptionsTests(ExecutionOptionsFixture):
    def test_template_defaults(self):
        policy = common.read_json(Path(server.__file__).parent / 'policy.json')
        self.assertEqual(policy['record_root'], '.codex-command-records')
        self.assertEqual(policy['output_quota_bytes'], 1048576)
        for name in ('native', 'script', 'python_unittest'):
            self.assertEqual(policy['operations'][name]['run_seconds'], 300)

    def test_defaults_are_frozen_in_prepared_request(self):
        _, business = self.prepare()
        self.assertEqual(business['run_seconds'], 300)
        self.assertEqual(business['output_quota_bytes'], 1048576)

    def test_explicit_limits_are_preserved(self):
        _, business = self.prepare(run_seconds=1800, output_quota_bytes=16777216)
        self.assertEqual(business['run_seconds'], 1800)
        self.assertEqual(business['output_quota_bytes'], 16777216)

    def test_minimum_limits_are_accepted(self):
        _, business = self.prepare(run_seconds=1, output_quota_bytes=1024)
        self.assertEqual(business['run_seconds'], 1)
        self.assertEqual(business['output_quota_bytes'], 1024)

    def test_invalid_limits_reject_before_claim_or_spawn(self):
        for key, invalid in (
                ('run_seconds', [0, -1, 1801, True, 1.5, '300', None]),
                ('output_quota_bytes', [0, 1023, 16777217, False, 1024.5, '1048576', None])):
            for value in invalid:
                with self.subTest(key=key, value=value), mock.patch.object(server.subprocess, 'Popen') as spawn:
                    with self.assertRaisesRegex(common.Invalid, key + '_range_'):
                        self.server.tool_start(dict(self.form, **{key: value}))
                    spawn.assert_not_called()
                    self.assertFalse((self.server.serve_root / '_claims').exists())

    def test_runtime_rechecks_untrusted_request_values(self):
        req = {'operation': 'native', 'program': 'git', 'args': [],
               'run_seconds': 1801, 'output_quota_bytes': 1048576}
        with mock.patch.object(entry_v2, 'syntax') as syntax:
            with self.assertRaisesRegex(common.Invalid, 'run_seconds_range_'):
                entry_v2.plan(req, self.policy, mock.Mock(), self.tmp)
        syntax.assert_not_called()

    def test_shape_restricts_options_to_execution(self):
        for operation in ('location', 'status', 'read_text'):
            with self.subTest(operation=operation):
                with self.assertRaisesRegex(common.Invalid, 'execution_options_require_execution_operation'):
                    common.shape({'task_ref': 'test', 'step_ref': operation,
                                  'cwd': str(self.tmp), 'operation': operation,
                                  'run_seconds': 30})

    def test_options_cannot_start_duplicate_running_business(self):
        first, _ = self.prepare()
        with mock.patch.object(server.subprocess, 'Popen') as spawn:
            changed = self.server.tool_start(dict(self.form, run_seconds=1800,
                                                 output_quota_bytes=16777216))
        spawn.assert_not_called()
        self.assertEqual(changed['execution_id'], first['execution_id'])
        self.assertTrue(changed['in_flight_dedup'])
        envelope = common.read_json(self.server.serve_root / first['execution_id'] / 'request.json')
        self.assertEqual(envelope['business']['run_seconds'], 300)

    def test_stdio_advertises_parameters_and_enforces_ranges(self):
        messages = [{'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'},
                    {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call',
                     'params': {'name': 'start_operation',
                                'arguments': dict(self.form, run_seconds=1801)}}]
        result = subprocess.run([sys.executable, '-X', 'utf8', str(Path(server.__file__)),
                                 '--policy', str(self.policy_path)],
                                input=''.join(json.dumps(m) + '\n' for m in messages),
                                capture_output=True, text=True, encoding='utf-8', timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        replies = [json.loads(line) for line in result.stdout.splitlines()]
        props = replies[0]['result']['tools'][0]['inputSchema']['properties']
        self.assertEqual(props['run_seconds']['maximum'], 1800)
        self.assertEqual(props['output_quota_bytes']['maximum'], 16777216)
        self.assertTrue(replies[1]['result']['isError'])
        self.assertIn('run_seconds_range_', replies[1]['result']['content'][0]['text'])

    def test_policy_bounds_match_request_contract(self):
        self.assertEqual(validate(self.policy), [])
        self.policy['output_quota_bytes'] = 16777216
        self.policy['operations']['native']['run_seconds'] = 1800
        self.assertEqual(validate(self.policy), [])
        self.policy['output_quota_bytes'] += 1
        self.policy['operations']['native']['run_seconds'] += 1
        problems = validate(self.policy)
        self.assertIn('output_quota_bytes_out_of_range', problems)
        self.assertIn('operation_budget_invalid:native', problems)


class ExecutionOptionsIntegrationTests(ExecutionOptionsFixture):
    # Select these methods explicitly for the slower end-to-end checks.
    def execute_script(self, code, **options):
        script = self.tmp / 'task.py'
        script.write_text(code, encoding='utf-8')
        business = {'task_ref': 'options-test', 'step_ref': 'one-write',
                    'operation': 'script', 'program': 'python', 'language': 'python',
                    'cwd': str(self.tmp), 'script': str(script), **options}
        req = common.shape(business)
        request = self.tmp / 'request.json'
        common.write_new(request, {'business': business, 'fingerprint': common.request_digest(req)})
        # Timer still runs normally; observing the argument avoids a 30 minute test.
        with mock.patch.object(entry_v2.threading, 'Timer', wraps=entry_v2.threading.Timer) as timer:
            result = entry_v2.run(request, self.policy_path)
        return result, timer, request

    def test_default_timer_and_output_exceed_old_64k(self):
        result, timer, _ = self.execute_script('import sys\nfor _ in range(1500):\n'
                                               '    print("x" * 100)\n'
                                               '    print("y" * 100, file=sys.stderr)\n')
        self.assertEqual(result['state'], 'exited', result.get('error'))
        self.assertEqual(result['process']['exit_code'], 0)
        self.assertEqual(timer.call_args.args[0], 300)
        self.assertEqual(result['output_quota_bytes'], 1048576)
        for stream in ('stdout', 'stderr'):
            self.assertGreater(result['output'][stream]['retained_utf8_bytes'], 65536)
            self.assertTrue(result['output'][stream]['retained_view_complete'])

    def test_override_output_paging_does_not_repeat_write(self):
        marker = self.tmp / 'writes.txt'
        code = ('from pathlib import Path\nimport sys\n'
                'with Path("writes.txt").open("a") as f: f.write("once\\n")\n'
                'for _ in range(12000):\n'
                '    print("x" * 100)\n'
                '    print("y" * 100, file=sys.stderr)\n')
        result, timer, request = self.execute_script(code, run_seconds=1800,
                                                     output_quota_bytes=2097152)
        self.assertEqual(result['state'], 'exited', result.get('error'))
        self.assertEqual(timer.call_args.args[0], 1800)
        self.assertEqual(result['output_quota_bytes'], 2097152)
        directory = Path(result['record_dir'])
        serve = self.server.serve_root / result['execution_id']
        serve.mkdir()
        common.write_new(serve / 'request.json', common.read_json(request))
        for stream in ('stdout', 'stderr'):
            metadata = result['output'][stream]
            self.assertGreater(metadata['retained_utf8_bytes'], 1048576)
            self.assertTrue(metadata['retained_view_complete'])
            original = (directory / (stream + '.txt')).read_text(encoding='utf-8')
            page = self.server.tool_output({'execution_id': result['execution_id'],
                                            'stream': stream, 'offset': len(original) - 100,
                                            'count': 100})
            self.assertEqual(page['text'], original[-100:])
            self.assertTrue(page['retained_view_end'])
        again = entry_v2.run(request, self.policy_path)
        self.assertTrue(again['duplicate_delivery'])
        self.assertEqual(again['execution_id'], result['execution_id'])
        self.assertEqual(marker.read_text(), 'once\n')

    def test_quota_loss_is_explicit_and_timeout_is_enforced(self):
        result, timer, _ = self.execute_script('import time\n'
                                               'for _ in range(100): print("x" * 100, flush=True)\n'
                                               'time.sleep(5)\n',
                                               run_seconds=1, output_quota_bytes=1024)
        self.assertEqual(timer.call_args.args[0], 1)
        self.assertEqual(result['state'], 'timed_out', result)
        self.assertEqual(result['business_observation']['alive'], False)
        metadata = result['output']['stdout']
        self.assertLessEqual(metadata['retained_utf8_bytes'], 1024)
        self.assertGreater(metadata['missing_lines'], 0)
        self.assertFalse(metadata['retained_view_complete'])

    def test_stdio_start_query_and_output_use_one_execution(self):
        script = self.tmp / 'stdio-task.py'
        script.write_text('from pathlib import Path\n'
                          'with Path("writes.txt").open("a") as f: f.write("once\\n")\n'
                          'print("stdio-result")\n', encoding='utf-8')
        with subprocess.Popen([sys.executable, '-X', 'utf8', str(Path(server.__file__)),
                               '--policy', str(self.policy_path)],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, encoding='utf-8') as host:
            sequence = 0

            def call(name, arguments):
                nonlocal sequence
                sequence += 1
                message = {'jsonrpc': '2.0', 'id': sequence, 'method': 'tools/call',
                           'params': {'name': name, 'arguments': arguments}}
                host.stdin.write(json.dumps(message) + '\n')
                host.stdin.flush()
                response = json.loads(host.stdout.readline())
                self.assertEqual(response['id'], sequence)
                self.assertFalse(response['result']['isError'], response)
                return response['result']['structuredContent']

            started = call('start_operation', {'operation': 'script', 'program': 'python',
                                               'language': 'python', 'script': str(script),
                                               'workdir': str(self.tmp), 'run_seconds': 25,
                                               'output_quota_bytes': 2097152})
            target = {'execution_id': started['execution_id']}
            deadline = time.monotonic() + 10
            status = call('status', target)
            while status['state'] not in server.TERMINAL and time.monotonic() < deadline:
                time.sleep(0.1)
                status = call('status', target)
            self.assertEqual(status['state'], 'exited', status)
            self.assertEqual(status['process']['exit_code'], 0)
            self.assertEqual(status['run_budget_seconds'], 25)
            self.assertEqual(status['output_quota_bytes'], 2097152)
            for _ in range(2):
                output = call('output', target)
                self.assertEqual(output['execution_id'], started['execution_id'])
                self.assertEqual(output['text'], 'stdio-result\n')
            self.assertEqual((self.tmp / 'writes.txt').read_text(), 'once\n')
            _, stderr = host.communicate(timeout=10)
            self.assertEqual(host.returncode, 0, stderr)


if __name__ == '__main__':
    unittest.main()
