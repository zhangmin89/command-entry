"""Stage 2 exec-server tests: all plan acceptance gates in-process.

Covers: start/dedup/new-intent identity rules, status/output, layered cancel,
wait semantics (budget/terminal/stop-after-two-stale-observations), read_text
A1 semantics (full coverage proof, segmented continuation, strict decode
failure, oversized single line, read_roots), orphan guarantee fail-closed,
and the crash-orphan gate: a hard-killed server must not kill in-flight work.
"""
import json
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import server as server_module  # noqa: E402


def wait_state(directory, predicate, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = server_module.entry_v2.snapshot(directory)
        if result['state'] in server_module.TERMINAL:
            return result
        if predicate and predicate(result):
            return result
        time.sleep(0.5)
    return server_module.entry_v2.snapshot(directory)


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix='exec-server-test '))
        cls.serve_root = cls.tmp / 'serve'
        cls.policy_path = cls.tmp / 'policy.json'
        cls.policy = {
            'version': 2,
            'python': sys.executable,
            'candidate_entry': str(ROOT / 'entry_v2.py'),
            'working_roots': [str(cls.tmp)],
            'record_root': '.codex-command-records',
            'serve_root': str(cls.serve_root),
            'read_roots': None,
            'programs': {'git': {'kind': 'native', 'path': r'C:\Program Files\Git\cmd\git.exe'},
                         'python': {'kind': 'python', 'path': sys.executable}},
            'operations': {'native': {'acceptable_exit_codes': [0], 'run_seconds': 60,
                                      'wait_category': 'long_task'},
                           'script': {'acceptable_exit_codes': [0], 'run_seconds': 60,
                                      'wait_category': 'long_task'}},
            'output_quota_bytes': 65536,
            'read_quota_bytes': 200,
            'cleanup_seconds': 5,
            'wait_budget_seconds': 15,
            'wait_poll_interval_seconds': 1,
            'cancel_grace_seconds': 12,
            'require_orphan_guarantee': False,
        }
        cls.policy_path.write_text(json.dumps(cls.policy), encoding='utf-8')
        cls.server = server_module.Server(cls.policy_path)

    def make_sleepy(self, name, seconds=30):
        """Per-case sleeping script: cases must not share mutable fixtures."""
        path = self.tmp / name
        path.write_text('import time\ntime.sleep(%d)\n' % seconds, encoding='utf-8')
        return str(path)

    def start(self, **overrides):
        form = {'operation': 'native', 'program': 'git', 'workdir': str(self.tmp),
                'args': ['--version']}
        form.update(overrides)
        return self.server.tool_start(form)

    def record_of(self, execution_id):
        business = json.loads((self.serve_root / execution_id / 'request.json')
                               .read_text(encoding='utf-8'))['business']
        return Path(business['cwd']) / '.codex-command-records' / execution_id

    # ---------- start / identity rules ----------

    def test_start_executes_to_terminal(self):
        result = self.start()
        self.assertFalse(result['in_flight_dedup'])
        terminal = wait_state(self.record_of(result['execution_id']), None)
        self.assertEqual(terminal['state'], 'exited')
        self.assertEqual(terminal['process']['exit_code'], 0)

    def test_same_content_running_dedups(self):
        script = self.make_sleepy('dedup-sleep.py')
        first = self.start(operation='script', program='python', language='python',
                           script=script, args=[])
        second = self.start(operation='script', program='python', language='python',
                            script=script, args=[])
        self.assertTrue(second['in_flight_dedup'])
        self.assertEqual(second['execution_id'], first['execution_id'])
        status = self.server.tool_status({'execution_id': first['execution_id']})
        self.assertNotIn('exited', (status['state'],))
        self.server.tool_cancel({'execution_id': first['execution_id']})

    def test_terminal_same_content_is_new_intent(self):
        first = self.start()
        wait_state(self.record_of(first['execution_id']), None)
        second = self.start()
        self.assertNotEqual(second['execution_id'], first['execution_id'])
        self.assertFalse(second['in_flight_dedup'])
        wait_state(self.record_of(second['execution_id']), None)

    def test_retry_via_previous_execution(self):
        retry_script = self.tmp / 'retry-sleep.py'
        retry_script.write_text('import time\ntime.sleep(30)\n', encoding='utf-8')
        first = self.start(operation='script', program='python', language='python',
                           script=str(retry_script), args=[])
        cancelled = self.server.tool_cancel({'execution_id': first['execution_id']})
        self.assertIn(cancelled['cancel_action'],
                      ('cancel_request_written_and_finished_within_grace',
                       'cancel_request_already_present_and_finished_within_grace'))
        terminal = wait_state(self.record_of(first['execution_id']), None)
        self.assertEqual(terminal['state'], 'cancelled')
        # Modify the bound script (sleep shorter), retry through the lineage.
        retry_script.write_text('import time\ntime.sleep(0.2)\n', encoding='utf-8')
        retry = self.start(operation='script', program='python', language='python',
                           script=str(retry_script), args=[],
                           previous_execution=first['execution_id'])
        self.assertFalse(retry['in_flight_dedup'])
        record = wait_state(self.record_of(retry['execution_id']), None)
        self.assertEqual(record['state'], 'exited')
        self.assertIn('changed_conditions', json.dumps(record))

    # ---------- status / output ----------

    def test_status_and_output_paging(self):
        script = self.tmp / 'lines.py'
        script.write_text('for i in range(5):\n    print(f"line-{i}")\n', encoding='utf-8')
        started = self.start(operation='script', program='python', language='python',
                             script=str(script), args=[])
        record = wait_state(self.record_of(started['execution_id']), None)
        self.assertEqual(record['state'], 'exited')
        status = self.server.tool_status({'execution_id': started['execution_id']})
        self.assertEqual(status['execution_id'], started['execution_id'])
        first = self.server.tool_output({'execution_id': started['execution_id'],
                                         'stream': 'stdout', 'offset': 0, 'count': 3})
        self.assertEqual(first['text'], 'lin')
        self.assertFalse(first['retained_view_end'])
        rest = self.server.tool_output({'execution_id': started['execution_id'],
                                        'stream': 'stdout', 'offset': first['next_offset']})
        self.assertTrue((first['text'] + rest['text']).startswith('line-0'))
        self.assertTrue(rest['retained_view_end'])

    # ---------- cancel ----------

    def test_cancel_graceful_within_grace(self):
        started = self.start(operation='script', program='python', language='python',
                             script=self.make_sleepy('cancel-sleep.py'), args=[])
        result = self.server.tool_cancel({'execution_id': started['execution_id']})
        self.assertIn('finished_within_grace', result['cancel_action'])
        record = wait_state(self.record_of(started['execution_id']), None)
        self.assertEqual(record['state'], 'cancelled')

    # ---------- wait ----------

    def test_wait_returns_terminal_for_finished(self):
        started = self.start()
        wait_state(self.record_of(started['execution_id']), None)
        result = self.server.tool_wait({'execution_id': started['execution_id']})
        self.assertEqual(result['wait_outcome'], 'terminal')
        self.assertEqual(result['state'], 'exited')

    def test_wait_stops_after_two_stale_observations(self):
        started = self.start(operation='script', program='python', language='python',
                             script=self.make_sleepy('wait-sleep.py'), args=[])
        try:
            result = self.server.tool_wait({'execution_id': started['execution_id']})
            self.assertEqual(result['wait_outcome'], 'stop_automatic_wait')
            self.assertEqual(result['no_progress_count'], 2)
            self.assertTrue(result['observation']['changed'] or
                            result['observation']['unknown_metrics'])
        finally:
            self.server.tool_cancel({'execution_id': started['execution_id']})

    # ---------- read_text (A1) ----------

    def test_read_text_small_file_full_coverage(self):
        small = self.tmp / 'small.txt'
        small.write_bytes(b'alpha\nbeta\ngamma\n')
        result = self.server.tool_read_text({'file': str(small), 'max_lines': 10})
        self.assertEqual(result['text'], 'alpha\nbeta\ngamma\n')
        self.assertEqual(result['total_lines'], 3)
        self.assertFalse(result['remaining'])
        self.assertFalse(result['decoding_loss'])

    def test_read_text_segmented_continuation(self):
        big = self.tmp / 'big.txt'
        content = ''.join('row-%03d\n' % i for i in range(300))
        big.write_bytes(content.encode('utf-8'))
        collected = ''
        start_line = 1
        while True:
            result = self.server.tool_read_text({'file': str(big), 'start_line': start_line,
                                                 'max_lines': 100})
            collected += result['text']
            if not result['remaining']:
                break
            start_line = result['next_start_line']
        self.assertEqual(collected, content)
        self.assertEqual(result['total_lines'], 300)

    def test_read_text_strict_decode_failure_structured(self):
        gbk_file = self.tmp / 'gbk.txt'
        gbk_file.write_bytes('中文内容'.encode('gbk'))
        result = self.server.tool_read_text({'file': str(gbk_file)})
        self.assertEqual(result['error'], 'decoding_failed_strict')
        self.assertIn('gbk', result['suggested_encodings'])
        again = self.server.tool_read_text({'file': str(gbk_file), 'encoding': 'gbk'})
        self.assertEqual(again['text'], '中文内容')
        self.assertEqual(again['encoding_used'], 'gbk')

    def test_read_text_oversized_single_line_errors(self):
        wide = self.tmp / 'wide.txt'
        wide.write_bytes(b'x' * 300 + b'\n')  # quota is 200
        result = self.server.tool_read_text({'file': str(wide)})
        self.assertEqual(result['error'], 'single_line_exceeds_quota')
        self.assertEqual(result['line_number'], 1)

    def test_read_text_outside_read_roots_rejected(self):
        outside = Path(tempfile.mkdtemp(prefix='outside-roots ')) / 'secret.txt'
        outside.write_text('secret\n', encoding='utf-8')
        with self.assertRaises(Exception) as caught:
            self.server.tool_read_text({'file': str(outside)})
        self.assertIn('file_outside_read_roots', str(caught.exception))

    # ---------- orphan guarantee ----------

    def test_require_orphan_guarantee_fails_closed(self):
        saved_flag = self.server.orphan_guaranteed
        try:
            self.server.orphan_guaranteed = False
            self.server.policy['require_orphan_guarantee'] = True
            with self.assertRaises(Exception) as caught:
                self.start()
            self.assertIn('orphan_guarantee_required_but_unavailable', str(caught.exception))
        finally:
            self.server.orphan_guaranteed = saved_flag
            self.server.policy['require_orphan_guarantee'] = False

    # ---------- crash orphan gate: hard-killed server must not kill work ----------

    def test_hard_killed_server_leaves_inflight_work_alive(self):
        long_sleep = self.tmp / 'six-second-sleep.py'
        long_sleep.write_text('import time\ntime.sleep(6)\n', encoding='utf-8')
        proc = subprocess.Popen([sys.executable, '-X', 'utf8', str(ROOT / 'server.py'),
                                 '--policy', str(self.policy_path)],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, encoding='utf-8', shell=False)

        def rpc(payload):
            proc.stdin.write(json.dumps(payload) + '\n')
            proc.stdin.flush()
            return json.loads(proc.stdout.readline())

        rpc({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
             'params': {'protocolVersion': '2025-06-18'}})
        answer = rpc({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call',
                      'params': {'name': 'start_operation',
                                 'arguments': {'operation': 'script', 'program': 'python',
                                               'language': 'python', 'script': str(long_sleep),
                                               'args': [], 'workdir': str(self.tmp)}}})
        started = answer['result']['structuredContent']
        execution_id = started['execution_id']
        record = self.record_of(execution_id)
        # Hard-kill the server while the business is running.
        proc.kill()
        proc.wait(timeout=10)
        terminal = wait_state(record, None, timeout=60)
        self.assertEqual(terminal['state'], 'exited')
        self.assertEqual(terminal['process']['exit_code'], 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
