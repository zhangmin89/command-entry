"""Black-box parity checks against the compiled C# server, without a test SDK dependency.

Test execution records are retained under .codex-command-records for diagnosis.
Set COMMAND_ENTRY_TEST_EXE to run the same contract against a Native AOT publish.
"""
import json
import hashlib
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
import unittest
import uuid

from common import digest, shape, request_digest
from server import Server
from windows_state import observe, terminate_if_same_instance

ROOT = Path(__file__).resolve().parents[1]
EXE = Path(os.environ.get('COMMAND_ENTRY_TEST_EXE', str(
    ROOT / 'src/CommandEntry/bin/Release/net10.0-windows/win-x64/CommandEntry.exe')))


class Client:
    def __init__(self, policy, binding=None):
        arguments = [str(EXE), '--policy', str(policy)]
        if binding is not None:
            arguments.extend(['--binding', str(binding)])
        self.process = subprocess.Popen(
            arguments, cwd=ROOT,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding='utf-8', shell=False,
            creationflags=subprocess.CREATE_NO_WINDOW)
        self.responses = queue.Queue()
        self.errors = []
        self.sequence = 0

        def read():
            for line in self.process.stdout:
                self.responses.put(json.loads(line))
            self.responses.put(None)

        def stderr():
            self.errors.extend(self.process.stderr)

        self.reader = threading.Thread(target=read, daemon=True)
        self.error_reader = threading.Thread(target=stderr, daemon=True)
        self.reader.start()
        self.error_reader.start()
        self.rpc('initialize', {'protocolVersion': '2025-06-18', 'capabilities': {},
                               'clientInfo': {'name': 'parity-test', 'version': '1'}})
        self.send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})

    def send(self, value):
        self.process.stdin.write(json.dumps(value) + '\n')
        self.process.stdin.flush()

    def rpc(self, method, parameters):
        self.sequence += 1
        identity = self.sequence
        self.send({'jsonrpc': '2.0', 'id': identity, 'method': method, 'params': parameters})
        while True:
            value = self.responses.get(timeout=60)
            if value is None:
                raise AssertionError('server EOF: ' + ''.join(self.errors))
            if value.get('id') != identity:
                continue
            if 'error' in value:
                raise AssertionError(value['error'])
            return value['result']

    def call(self, name, **arguments):
        result = self.rpc('tools/call', {'name': name, 'arguments': arguments})
        if result.get('isError'):
            raise AssertionError(result['content'])
        return result['structuredContent']

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
        self.reader.join(timeout=5)
        self.error_reader.join(timeout=5)
        for pipe in (self.process.stdin, self.process.stdout, self.process.stderr):
            pipe.close()


class CSharpMigrationTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(EXE.is_file(), f'Build the C# project first: {EXE}')
        self.directory = ROOT / '.codex-command-records' / ('csharp-test-' + str(uuid.uuid4()))
        self.directory.mkdir(parents=True)
        self.policy = json.loads((ROOT / 'policy.json').read_text(encoding='utf-8'))
        self.policy.update(working_roots=[str(self.directory)], read_roots=None,
                           serve_root=str(self.directory / 'serve-input'),
                           log_root=str(self.directory / 'logs'))
        self.policy['programs']['python']['path'] = sys.executable
        self.policy['programs']['probe'] = {'kind': 'native', 'path': str(EXE)}
        self.policy_file = self.directory / 'policy.json'
        self.policy_file.write_text(json.dumps(self.policy), encoding='utf-8')
        self.client = Client(self.policy_file)
        self.addCleanup(self.client.close)

    def script(self, name, code):
        path = self.directory / name
        path.write_text(code, encoding='utf-8')
        return path

    def start(self, script, **options):
        return self.client.call('start_operation', operation='script', program='python',
                                language='python', script=str(script),
                                workdir=str(self.directory), **options)

    def terminal(self, identity, seconds=30):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            state = self.client.call('status', execution_id=identity)
            if state['state'] in ('exited', 'rejected', 'timed_out', 'cancelled', 'unknown', 'tool_error', 'start_failed'):
                return state
            time.sleep(0.1)
        self.fail(f'execution did not terminate within {seconds}s: {identity}')

    def restart(self):
        self.client.close()
        self.policy_file.write_text(json.dumps(self.policy), encoding='utf-8')
        self.client = Client(self.policy_file)
        self.addCleanup(self.client.close)

    def test_tool_schema_and_invalid_budget(self):
        tools = self.client.rpc('tools/list', {})['tools']
        self.assertEqual({t['name'] for t in tools}, {'start_operation', 'status', 'output', 'cancel', 'wait', 'read_text'})
        for invalid in (True, None, 0, 1801, '30', 1.5):
            with self.subTest(invalid=invalid):
                result = self.client.rpc('tools/call', {'name': 'start_operation', 'arguments': {
                    'operation': 'native', 'program': 'probe', 'args': ['location'],
                    'workdir': str(self.directory), 'run_seconds': invalid}})
                self.assertTrue(result['isError'])
        self.assertEqual(list((self.directory / 'serve-input').glob('*/request.json')), [])

    def test_native_identity_and_location(self):
        form = {'operation': 'native', 'program': 'probe', 'workdir': str(self.directory), 'args': ['location']}
        started = self.client.call('start_operation', **form)
        state = self.terminal(started['execution_id'])
        self.assertEqual(state['state'], 'exited', state)
        self.assertEqual(state['process']['exit_code'], 0)
        envelope = json.loads((self.directory / 'serve-input' / started['execution_id'] / 'request.json').read_text())
        expected = shape(envelope['business'])
        self.assertEqual(envelope['fingerprint'], request_digest(expected))
        self.assertEqual(envelope['content_fingerprint'], digest(form))
        self.assertEqual(state['request_id'], expected['request_id'])
        result = self.client.call('output', execution_id=started['execution_id'])
        self.assertEqual(json.loads(result['text'])['cwd'], str(self.directory))

    def test_arguments_stdin_and_no_console(self):
        script = self.script('参数 probe.py', 'import ctypes,json,os,sys\n'
            'print(json.dumps({"args":sys.argv[1:],"stdin":list(sys.stdin.buffer.read()),'
            '"console":ctypes.windll.kernel32.GetConsoleWindow(),"cwd":os.getcwd()}))\n'
            'sys.exit(7)\n')
        arguments = ['', 'a b', '"quoted"', 'x\\', '&|%$()`', '中文😀', 'x\\"y']
        stdin = self.directory / 'stdin.bin'
        stdin.write_bytes(bytes(range(256)))
        started = self.start(script, args=arguments, stdin_file=str(stdin))
        state = self.terminal(started['execution_id'])
        self.assertEqual(state['state'], 'exited', state)
        self.assertEqual(state['process']['exit_code'], 7)
        self.assertFalse(state['operation_result']['acceptable_exit'])
        output = self.client.call('output', execution_id=started['execution_id'])
        actual = json.loads(output['text'])
        self.assertEqual(actual, {'args': arguments, 'stdin': list(range(256)), 'console': 0, 'cwd': str(self.directory)})

    def test_output_redaction_quota_and_unicode_offsets(self):
        script = self.script('output.py', 'import sys\n'
            'sys.stdout.buffer.write(("😀中文\\npassword=synthetic-fixture\\n" + "x"*100+"\\n").encode()*100)\n'
            'sys.stderr.buffer.write(b"tail\\n")\n')
        started = self.start(script, output_quota_bytes=1024)
        state = self.terminal(started['execution_id'])
        self.assertEqual(state['state'], 'exited', state)
        out = state['output']['stdout']
        self.assertTrue(out['capture_complete'])
        self.assertLessEqual(out['retained_utf8_bytes'], 1024)
        self.assertGreater(out['missing_lines'], 0)
        self.assertTrue(out['redacted'])
        text = self.client.call('output', execution_id=started['execution_id'], offset=1, count=2)['text']
        self.assertEqual(text, '中文')
        retained = self.client.call('output', execution_id=started['execution_id'], count=4096)['text']
        self.assertNotIn('synthetic-fixture', retained)
        self.assertEqual(self.client.call('output', execution_id=started['execution_id'], stream='stderr')['text'], 'tail\n')

    def test_text_ranges_match_python(self):
        reference = Server(self.policy_file)
        cases = [('utf8.txt', '甲😀\r\n乙\v丙\u2028last'.encode(), None),
                 ('gbk.txt', '中文\r\n第二行'.encode('gbk'), 'gbk'),
                 ('be.txt', b'\xfe\xff' + ('甲\n' * 22000 + '末').encode('utf-16-be'), None),
                 ('bad.txt', b'good\n\xffbad', None)]
        keys = ('text', 'lines_served', 'total_lines', 'total_lines_known', 'remaining', 'next_start_line', 'encoding_used')
        for name, data, encoding in cases:
            path = self.directory / name
            path.write_bytes(data)
            for start, count in ((1, 1), (2, 2), (1, 1000)):
                with self.subTest(name=name, start=start, count=count):
                    form = {'file': str(path), 'start_line': start, 'max_lines': count}
                    if encoding:
                        form['encoding'] = encoding
                    expected = reference.tool_read_text(form)
                    actual = self.client.call('read_text', **form)
                    if 'error' in expected:
                        self.assertEqual(actual.get('error'), expected['error'])
                    else:
                        self.assertEqual({k: actual[k] for k in keys}, {k: expected[k] for k in keys})

    def test_timeout_and_duplicate_delivery(self):
        script = self.script('sleep.py', 'import time\ntime.sleep(10)\n')
        started = self.start(script, run_seconds=2)
        repeated = self.start(script, run_seconds=20)
        self.assertEqual(repeated['execution_id'], started['execution_id'])
        self.assertTrue(repeated['in_flight_dedup'])
        state = self.terminal(started['execution_id'])
        self.assertEqual(state['state'], 'timed_out', state)
        self.assertEqual(state['run_budget_seconds'], 2)
        self.assertFalse(state['worker_observation']['alive'])

    def test_retry_requires_changed_bound_input(self):
        script = self.script('retry.py', 'print("first")\n')
        first = self.start(script)
        self.assertEqual(self.terminal(first['execution_id'])['state'], 'exited')
        unchanged = self.start(script, previous_execution=first['execution_id'])
        rejected = self.terminal(unchanged['execution_id'])
        self.assertEqual(rejected['state'], 'rejected', rejected)
        self.assertIn('verified_changed_conditions_required', rejected['error']['reason'])
        script.write_text('print("second")\n', encoding='utf-8')
        changed = self.start(script, previous_execution=unchanged['execution_id'])
        state = self.terminal(changed['execution_id'])
        self.assertEqual(state['state'], 'exited', state)
        self.assertIn(str(script), state['changed_conditions'])
        self.assertEqual(self.client.call('output', execution_id=changed['execution_id'])['text'], 'second\n')

    def test_cancel_confirms_worker_and_business_exit(self):
        script = self.script('cancel.py', 'import time\ntime.sleep(40)\n')
        started = self.start(script)
        result = self.client.call('cancel', execution_id=started['execution_id'])
        self.assertEqual(result['state'], 'cancelled', result)
        state = self.terminal(started['execution_id'])
        self.assertFalse(state['worker_observation']['alive'])
        birth = state['business_start']
        observation = observe(birth['pid'])
        self.assertTrue(observation['alive'] is False or observation['creation_time'] != birth['creation_time'])

    def test_wait_stops_on_observed_no_progress(self):
        self.policy.update(wait_poll_interval_seconds=1, wait_budget_seconds=4, wait_stop_after_no_progress=2)
        self.restart()
        script = self.script('wait.py', 'import time\ntime.sleep(12)\n')
        started = self.start(script)
        result = self.client.call('wait', execution_id=started['execution_id'])
        self.assertEqual(result['wait_outcome'], 'stop_automatic_wait', result)
        self.assertGreaterEqual(result['no_progress_count'], 2)
        self.assertTrue(result['observation']['process_alive'])
        self.assertFalse(result['observation']['progress_confirmed'])
        self.assertEqual(self.terminal(started['execution_id'])['state'], 'exited')

    def test_second_server_reuses_running_claim_and_heals_corruption(self):
        script = self.script('shared.py', 'import time\ntime.sleep(4)\n')
        first = self.start(script)
        path = self.directory / 'serve-input' / first['execution_id'] / 'request.json'
        fingerprint = json.loads(path.read_text())['content_fingerprint']
        claim = self.directory / 'serve-input' / '_claims' / fingerprint / 'claim.json'
        claim.write_text('{broken', encoding='utf-8')
        second = Client(self.policy_file)
        self.addCleanup(second.close)
        result = second.call('start_operation', operation='script', program='python', language='python',
                             script=str(script), workdir=str(self.directory), run_seconds=20)
        self.assertEqual(result['execution_id'], first['execution_id'])
        self.assertTrue(result['in_flight_dedup'])
        self.assertEqual(json.loads(claim.read_text())['execution_id'], first['execution_id'])
        self.assertEqual(self.terminal(first['execution_id'])['state'], 'exited')

    def test_unknown_blocks_restart_until_cancel_confirms_abandonment(self):
        self.policy.update(cancel_grace_seconds=1, cancel_confirm_seconds=2)
        self.restart()
        script = self.script('abandon.py', 'import time\ntime.sleep(3)\n')
        first = self.start(script)
        record = Path(first['record_dir']) / 'result.json'
        state = json.loads(record.read_text())
        owner = state['owner']
        self.assertTrue(terminate_if_same_instance(owner['pid'], owner['creation_time'])['terminated'])
        deadline = time.monotonic() + 5
        while observe(owner['pid'])['alive'] is True and time.monotonic() < deadline:
            time.sleep(0.1)
        repeated = self.start(script)
        self.assertEqual(repeated['execution_id'], first['execution_id'])
        self.assertTrue(repeated['dedup_blocked'])
        cancelled = self.client.call('cancel', execution_id=first['execution_id'])
        self.assertTrue(cancelled['confirmed_dead'], cancelled)
        self.assertEqual(self.client.call('status', execution_id=first['execution_id'])['state'], 'unknown')
        next_intent = self.start(script)
        self.assertNotEqual(next_intent['execution_id'], first['execution_id'])
        self.assertEqual(self.terminal(next_intent['execution_id'])['state'], 'exited')

    def test_owner_survives_server_exit(self):
        script = self.script('survive.py', 'import time\ntime.sleep(2)\nprint("survived")\n')
        first = self.start(script)
        self.client.process.kill()
        self.client.process.wait(timeout=10)
        self.client.close()
        self.client = Client(self.policy_file)
        self.addCleanup(self.client.close)
        state = self.terminal(first['execution_id'])
        self.assertEqual(state['state'], 'exited', state)
        self.assertEqual(self.client.call('output', execution_id=first['execution_id'])['text'], 'survived\n')

    def test_publication_failure_is_queryable_without_business_start(self):
        form = {'operation': 'native', 'program': 'probe', 'workdir': str(self.directory), 'args': ['location']}
        claim_directory = self.directory / 'serve-input' / '_claims' / digest(form)
        (claim_directory / 'claim.json').mkdir(parents=True)
        result = self.client.call('start_operation', **form)
        self.assertEqual(result['state'], 'start_failed', result)
        self.assertFalse(Path(result['record_dir']).exists())
        self.assertEqual(self.client.call('status', execution_id=result['execution_id'])['state'], 'start_failed')
        self.assertEqual(self.client.call('cancel', execution_id=result['execution_id'])['cancel_action'], 'already_terminal')

    def test_syntax_and_batch_rejections_precede_execution(self):
        script = self.script('invalid.py', 'if syntax broken\n')
        started = self.start(script)
        state = self.terminal(started['execution_id'])
        self.assertEqual(state['state'], 'rejected', state)
        self.assertIn('script_syntax_check_failed', state['error']['reason'])
        batch = self.script('not-native.cmd', '@echo SHOULD_NOT_EXECUTE\n')
        self.policy['programs']['batch'] = {'kind': 'native', 'path': str(batch)}
        self.restart()
        started = self.client.call('start_operation', operation='native', program='batch', workdir=str(self.directory))
        state = self.terminal(started['execution_id'])
        self.assertEqual(state['state'], 'rejected', state)
        self.assertIn('native_requires_exe', state['error']['reason'])
        self.assertFalse((Path(started['record_dir']) / 'business-process.json').exists())

    def test_acceptance_is_distinct_from_exit_success(self):
        output = self.directory / 'artifact.json'
        script = self.script('artifact.py', 'from pathlib import Path\nPath("artifact.json").write_text(\'{"n":2}\')\n')
        conditions = [{'kind': 'json_equals', 'artifact': 'result', 'keys': ['n'], 'expected': 3}]
        started = self.start(script, artifacts={'result': str(output)}, acceptance=conditions)
        state = self.terminal(started['execution_id'])
        self.assertEqual(state['state'], 'exited', state)
        self.assertTrue(state['operation_result']['acceptable_exit'])
        self.assertEqual(state['subgoal']['status'], 'not_fulfilled')
        self.assertFalse(state['subgoal']['evidence'][0]['matches'])

    def test_policy_and_binding_tampering_fail_closed(self):
        self.policy_file.write_text(json.dumps(dict(self.policy, read_quota_bytes=12)), encoding='utf-8')
        result = self.client.rpc('tools/call', {'name': 'start_operation', 'arguments': {
            'operation': 'native', 'program': 'probe', 'workdir': str(self.directory), 'args': ['location']}})
        self.assertTrue(result['isError'])
        self.assertIn('policy_changed_since_review', result['content'][0]['text'])
        binding = self.directory / 'binding.json'
        binding.write_text(json.dumps({'schema_version': 2,
            'policy': {'path': str(self.policy_file), 'sha256': hashlib.sha256(self.policy_file.read_bytes()).hexdigest()},
            'runtime_files': [{'path': str(EXE), 'sha256': '0' * 64}]}), encoding='utf-8')
        failed = subprocess.run([str(EXE), '--policy', str(self.policy_file), '--binding', str(binding)],
            cwd=ROOT, stdin=subprocess.DEVNULL, capture_output=True, text=True, encoding='utf-8',
            shell=False, creationflags=subprocess.CREATE_NO_WINDOW, timeout=20)
        self.assertEqual(failed.returncode, 125)
        self.assertIn('runtime_changed_since_review', failed.stderr)

    def test_binding_builder_creates_usable_non_overwriting_anchor(self):
        binding = self.directory / 'native-binding.json'
        arguments = [self.policy['powershell'], '-NoProfile', '-File',
            str(ROOT / 'scripts' / 'build-dotnet-binding.ps1'),
            '-RuntimeRoot', str(EXE.parent), '-PolicyPath', str(self.policy_file), '-OutputPath', str(binding)]
        result = subprocess.run(arguments, cwd=ROOT, stdin=subprocess.DEVNULL, capture_output=True,
            shell=False, creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['files'], 4)
        pinned = binding.read_bytes()
        anchor = json.loads(pinned)
        self.assertEqual({Path(item['path']).name for item in anchor['runtime_files']},
                         {'CommandEntry.exe', 'invoke.ps1', 'check_powershell.ps1', 'check_python.py'})
        bound = Client(self.policy_file, binding)
        self.addCleanup(bound.close)
        self.assertEqual(len(bound.rpc('tools/list', {})['tools']), 6)
        again = subprocess.run(arguments, cwd=ROOT, stdin=subprocess.DEVNULL, capture_output=True,
            shell=False, creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
        self.assertNotEqual(again.returncode, 0)
        self.assertIn(b'Refusing to overwrite an existing binding:', again.stderr)
        self.assertEqual(binding.read_bytes(), pinned)


if __name__ == '__main__':
    unittest.main()
