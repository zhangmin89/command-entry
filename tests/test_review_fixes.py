"""Review R1-R10 fix coverage (2026-09-14 deep review).

R1 claim protocol (cross-instance dedup / pending block / republish),
R2 fingerprint normalization, R3 unknown-blocks + sidecar unlock,
R5 unconfirmed_start recovery surface, R6/R7 streaming read_text semantics,
R8 read_roots=[] deny-all, R9 budget_exhausted real observation,
R10 rejected-log reason codes.
"""
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import common  # noqa: E402
import server as server_module  # noqa: E402


def make_policy(tmp, **overrides):
    policy = {
        'version': 2,
        'python': sys.executable,
        'working_roots': [str(tmp)],
        'record_root': '.codex-command-records',
        'serve_root': str(tmp / 'serve'),
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
        'wait_stop_after_no_progress': 12,
        'cancel_grace_seconds': 12,
        'cancel_confirm_seconds': 5,
        'claim_timeout_seconds': 30,
        'start_confirm_seconds': 3,
        'require_orphan_guarantee': False,
    }
    policy.update(overrides)
    policy_path = tmp / 'policy.json'
    policy_path.write_text(json.dumps(policy), encoding='utf-8')
    return policy, policy_path


def until_terminal(record, timeout=40):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = server_module.entry_v2.snapshot(record)['state']
        if state in server_module.TERMINAL:
            return state
        time.sleep(0.3)
    return 'wait_timeout'


class ClaimProtocolTests(unittest.TestCase):
    """R1/R2: cross-instance claim, normalization, pending block."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix='review-claim '))
        cls.policy, cls.policy_path = make_policy(cls.tmp)
        cls.server_a = server_module.Server(cls.policy_path)
        cls.server_b = server_module.Server(cls.policy_path)

    def sleepy(self, name, seconds=30):
        # Never rewrite while a prior execution may hold a FileLocks
        # deny-write handle on this script — that handle is the system
        # working as designed, and rewriting would fail (and should).
        path = self.tmp / name
        if not path.is_file():
            path.write_text('import time\ntime.sleep(%d)\n' % seconds, encoding='utf-8')
        return str(path)

    def form(self, **overrides):
        base = {'operation': 'script', 'program': 'python', 'language': 'python',
                'script': self.sleepy('claim-sleep.py'), 'workdir': str(self.tmp)}
        base.update(overrides)
        return base

    def test_cross_instance_dedup_via_claim(self):
        first = self.server_a.tool_start(self.form(args=[]))
        second = self.server_b.tool_start(self.form(args=[]))
        self.assertTrue(second['in_flight_dedup'])
        self.assertEqual(second['execution_id'], first['execution_id'])
        self.server_a.tool_cancel({'execution_id': first['execution_id']})

    def test_omitted_args_matches_empty_args(self):
        # R2: form without 'args' and form with args=[] are one identity.
        form_without = self.form()
        form_without.pop('args', None)
        first = self.server_a.tool_start(form_without)
        second = self.server_b.tool_start(self.form(args=[]))
        self.assertEqual(second['execution_id'], first['execution_id'])
        self.assertTrue(second['in_flight_dedup'])
        self.server_a.tool_cancel({'execution_id': first['execution_id']})

    def test_pending_claim_blocks_without_starting(self):
        content = {'operation': 'native', 'program': 'git', 'workdir': str(self.tmp.resolve()),
                   'args': ['--version']}
        fingerprint = common.digest(content)
        outcome, _, claim_dir = self.server_a.claim_execution(fingerprint)
        self.assertEqual(outcome, 'claim')  # A holds an UNFINISHED claim
        outcome_b, exec_id, _ = self.server_b.claim_execution(fingerprint)
        self.assertEqual(outcome_b, 'pending')
        self.assertIsNone(exec_id)
        with self.assertRaises(Exception) as caught:
            self.server_b.tool_start({'operation': 'native', 'program': 'git',
                                      'workdir': str(self.tmp), 'args': ['--version']})
        self.assertIn('claim_pending_unconfirmed', str(caught.exception))
        claim_dir.rmdir()  # test cleanup: release the unfinished claim

    def test_terminal_republishes_claim_to_new_intent(self):
        form = {'operation': 'native', 'program': 'git', 'workdir': str(self.tmp),
                'args': ['--version']}
        first = self.server_a.tool_start(form)
        record = Path(first['record_dir'])
        self.assertEqual(until_terminal(record), 'exited')
        second = self.server_b.tool_start(form)
        self.assertNotEqual(second['execution_id'], first['execution_id'])
        self.assertFalse(second['in_flight_dedup'])
        claim_file = self.server_a.serve_root / '_claims' / self._fingerprint_of(form) / 'claim.json'
        self.assertEqual(json.loads(claim_file.read_text(encoding='utf-8'))['execution_id'],
                         second['execution_id'])
        until_terminal(Path(second['record_dir']))

    def _fingerprint_of(self, form):
        content = {k: v for k, v in form.items() if v is not None}
        content['args'] = content.get('args') or []
        content['workdir'] = str(Path(form['workdir']).resolve())
        return common.digest(content)


class UnknownBlockingTests(unittest.TestCase):
    """R3: unknown is not terminal; sidecar-confirmed death unlocks."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix='review-unknown '))
        cls.policy, cls.policy_path = make_policy(cls.tmp, cancel_grace_seconds=3)
        cls.server = server_module.Server(cls.policy_path)

    def test_unknown_blocks_then_sidecar_unlocks(self):
        script = self.tmp / 'sleepy.py'
        script.write_text('import time\ntime.sleep(60)\n', encoding='utf-8')
        form = {'operation': 'script', 'program': 'python', 'language': 'python',
                'script': str(script), 'args': [], 'workdir': str(self.tmp)}
        started = self.server.tool_start(form)
        record = Path(started['record_dir'])
        # Force 'unknown': kill the entry child (owner). KILL_ON_JOB_CLOSE
        # takes the business down with it; snapshot then reports unknown.
        result = json.loads((record / 'result.json').read_text(encoding='utf-8'))
        owner = result['owner']
        server_module.terminate_if_same_instance(owner['pid'], owner['creation_time'])
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.server.snapshot(record)['state'] == 'unknown':
                break
            time.sleep(0.3)
        self.assertEqual(self.server.snapshot(record)['state'], 'unknown')
        # A duplicate start must be blocked, not silently spawned.
        blocked = self.server.tool_start(form)
        self.assertTrue(blocked['dedup_blocked'])
        self.assertEqual(blocked['execution_id'], started['execution_id'])
        # Cancel confirms death via the sidecar; record stays unknown.
        cancelled = self.server.tool_cancel({'execution_id': started['execution_id']})
        self.assertEqual(cancelled['cancel_action'], 'hard_kill_after_grace')
        self.assertTrue(cancelled['confirmed_dead'])
        self.assertEqual(self.server.snapshot(record)['state'], 'unknown')
        self.assertTrue((record / 'cancel-outcome.json').is_file())
        # Now a new intent is allowed.
        fresh = self.server.tool_start(form)
        self.assertNotEqual(fresh['execution_id'], started['execution_id'])
        self.assertFalse(fresh.get('dedup_blocked'))
        self.server.tool_cancel({'execution_id': fresh['execution_id']})


class StartFailureSurfaceTests(unittest.TestCase):
    """R5: failed starts keep the execution id recoverable."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix='review-startfail '))
        cls.policy, cls.policy_path = make_policy(cls.tmp, start_confirm_seconds=1)
        cls.server = server_module.Server(cls.policy_path)

    def test_unconfirmed_start_returns_id_and_serve_error(self):
        serve_dir_holder = {}

        def fake_popen(command, **kwargs):
            record_dir = Path(command[command.index('--record-dir') + 1])
            serve_dir_holder['dir'] = record_dir
            common.write_new(record_dir / 'serve-error.json',
                             {'state': 'not_started', 'error': {'kind': 'Invalid', 'reason': 'boom'}})
            return object()

        with mock.patch.object(server_module.subprocess, 'Popen', fake_popen):
            result = self.server.tool_start({'operation': 'native', 'program': 'git',
                                             'workdir': str(self.tmp), 'args': ['--version']})
        self.assertEqual(result['state'], 'unconfirmed_start')
        self.assertIn('execution_id', result)
        self.assertEqual(result['serve_error']['error']['reason'], 'boom')
        # The claim was published: a duplicate start classifies, never spawns.
        again = self.server.tool_start({'operation': 'native', 'program': 'git',
                                        'workdir': str(self.tmp), 'args': ['--version']})
        self.assertEqual(again['execution_id'], result['execution_id'])
        self.assertTrue(again['dedup_blocked'])


class StreamingReadTextTests(unittest.TestCase):
    """R6/R7/R8: line semantics, streaming bounds, deny-all roots."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix='review-read '))
        cls.policy, cls.policy_path = make_policy(cls.tmp)
        cls.server = server_module.Server(cls.policy_path)

    def read(self, **form):
        return self.server.tool_read_text(form)

    def test_cr_line_endings_paged_correctly(self):
        path = self.tmp / 'cr.txt'
        path.write_bytes(b'one\rtwo\rthree\r')
        first = self.read(file=str(path), start_line=1, max_lines=2)
        self.assertEqual(first['text'], 'one\rtwo\r')
        self.assertEqual(first['lines_served'], 2)
        self.assertEqual(first['next_start_line'], 3)
        self.assertTrue(first['remaining'])
        second = self.read(file=str(path), start_line=first['next_start_line'])
        self.assertEqual(second['text'], 'three\r')
        self.assertEqual(second['total_lines'], 3)
        self.assertFalse(second['remaining'])

    def test_unicode_line_separator(self):
        path = self.tmp / 'u2028.txt'
        path.write_text('a\u2028b\u2028', encoding='utf-8')
        result = self.read(file=str(path))
        self.assertEqual(result['lines_served'], 2)
        self.assertEqual(result['total_lines'], 2)

    def test_total_lines_unknown_when_scan_stops_early(self):
        path = self.tmp / 'many.txt'
        path.write_text(''.join('row-%03d\n' % i for i in range(300)), encoding='utf-8')
        self.server.policy['read_quota_bytes'] = 1048576
        try:
            result = self.read(file=str(path), start_line=1, max_lines=100)
            self.assertEqual(result['lines_served'], 100)
            self.assertIsNone(result['total_lines'])
            self.assertFalse(result['total_lines_known'])
            self.assertTrue(result['remaining'])
            full = self.read(file=str(path), start_line=1, max_lines=1000)
            self.assertEqual(full['total_lines'], 300)
            self.assertTrue(full['total_lines_known'])
        finally:
            self.server.policy['read_quota_bytes'] = 200

    def test_single_line_quota_enforced_mid_scan(self):
        path = self.tmp / 'wide-mid.txt'
        path.write_bytes(b'short\n' + b'x' * 300 + b'\ntail\n')  # quota is 200
        result = self.read(file=str(path))
        self.assertEqual(result['error'], 'single_line_exceeds_quota')
        self.assertEqual(result['line_number'], 2)

    def test_late_decode_error_does_not_fail_early_range(self):
        path = self.tmp / 'mixed.txt'
        path.write_bytes(b'line1\nline2\n' + '中文'.encode('gbk') + b'\n')
        result = self.read(file=str(path), start_line=1, max_lines=2)
        self.assertEqual(result['lines_served'], 2)
        self.assertEqual(result['text'], 'line1\nline2\n')

    def test_empty_read_roots_denies_everything(self):
        path = self.tmp / 'inside.txt'
        path.write_text('data\n', encoding='utf-8')
        self.server.policy['read_roots'] = []
        try:
            with self.assertRaises(Exception) as caught:
                self.read(file=str(path))
            self.assertIn('file_outside_read_roots', str(caught.exception))
        finally:
            self.server.policy['read_roots'] = None


class WaitObservationTests(unittest.TestCase):
    """R9: budget_exhausted reports the real observation."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix='review-wait '))
        cls.policy, cls.policy_path = make_policy(
            cls.tmp, wait_budget_seconds=3, wait_poll_interval_seconds=1,
            wait_stop_after_no_progress=99)
        cls.server = server_module.Server(cls.policy_path)

    def test_budget_exhausted_reports_actual_progress(self):
        # Progress signal: an artifact file appended each tick. CPU-time
        # deltas can vanish within timer resolution for a sleepy process;
        # artifact size/mtime is the robust observable.
        log = self.tmp / 'ticks.log'
        script = self.tmp / 'chatty.py'
        script.write_text('import time\nfrom pathlib import Path\n'
                          'for i in range(30):\n'
                          '    with Path(%r).open("a") as stream:\n'
                          '        stream.write("tick %%d\\n" %% i)\n'
                          '    time.sleep(0.3)\n' % str(log), encoding='utf-8')
        started = self.server.tool_start({'operation': 'script', 'program': 'python',
                                          'language': 'python', 'script': str(script),
                                          'args': [], 'workdir': str(self.tmp),
                                          'artifacts': {'log': str(log)}})
        try:
            result = self.server.tool_wait({'execution_id': started['execution_id']})
            self.assertEqual(result['wait_outcome'], 'budget_exhausted')
            self.assertIsNotNone(result['observation'])
            self.assertTrue(result['observation']['progress_confirmed'])
        finally:
            self.server.tool_cancel({'execution_id': started['execution_id']})


class RejectionLogTests(unittest.TestCase):
    """R10: rejected events carry a classifiable reason code."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix='review-log '))
        cls.policy, cls.policy_path = make_policy(cls.tmp)
        cls.server = server_module.Server(cls.policy_path)

    def test_rejected_logs_reason_code(self):
        with self.assertRaises(Exception):
            self.server.dispatch('start_operation', {'operation': 'native', 'program': 'ghost',
                                                     'workdir': str(self.tmp), 'args': []})
        events = (self.server.log_root / 'server-events.jsonl').read_text(encoding='utf-8')
        rejected = [json.loads(line) for line in events.splitlines()
                    if json.loads(line).get('kind') == 'rejected']
        self.assertTrue(rejected)
        self.assertEqual(rejected[-1]['reason'], 'program_not_configured')
        self.assertEqual(rejected[-1]['kind'], 'rejected')


if __name__ == '__main__':
    unittest.main(verbosity=2)
