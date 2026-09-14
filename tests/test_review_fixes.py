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
        with self.server_a.claim_section(fingerprint) as section_a:
            self.assertEqual(section_a[0], 'claim')  # A holds the section
            with self.server_b.claim_section(fingerprint) as section_b:
                self.assertEqual(section_b[0], 'pending')  # live contention
            with self.assertRaises(Exception) as caught:
                self.server_b.tool_start({'operation': 'native', 'program': 'git',
                                          'workdir': str(self.tmp), 'args': ['--version']})
            self.assertIn('claim_pending_unconfirmed', str(caught.exception))
        # Section released without publishing: the claim is simply re-taken.
        with self.server_b.claim_section(fingerprint) as section_c:
            self.assertEqual(section_c[0], 'claim')

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

    def test_cancel_confirms_worker_too(self):
        # R3 follow-up: 'all known processes' includes the worker host named
        # in the record, not just owner + business-process.json.
        execution_id = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc'
        serve_dir = self.server.serve_root / execution_id
        serve_dir.mkdir(parents=True)
        business = {'task_ref': 't', 'step_ref': 's', 'operation': 'native',
                    'cwd': str(self.tmp), 'program': 'git', 'args': ['--version']}
        content = {'operation': 'native', 'program': 'git',
                   'workdir': str(self.tmp.resolve()), 'args': ['--version']}
        fingerprint = common.digest(content)
        common.write_new(serve_dir / 'request.json',
                         {'schema_version': 2, 'business': business,
                          'content_fingerprint': fingerprint})
        record = self.tmp / '.codex-command-records' / execution_id
        record.mkdir(parents=True)
        # Fake pids: OpenProcess fails with ERROR_INVALID_PARAMETER, which
        # terminate_and_confirm treats as confirmed dead by observation.
        common.write_new(record / 'result.json', {
            'state': 'running', 'execution_id': execution_id,
            'request_id': 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
            'owner': {'pid': 99999901, 'creation_time': 111},
            'worker': {'pid': 99999902, 'creation_time': 222},
            'process': {'exit_code': None}, 'subgoal': {'status': 'unknown'}})
        form = {'operation': 'native', 'program': 'git', 'workdir': str(self.tmp),
                'args': ['--version']}
        blocked = self.server.tool_start(form)
        self.assertTrue(blocked['dedup_blocked'])
        cancelled = self.server.tool_cancel({'execution_id': execution_id})
        self.assertIn('worker', cancelled['detail'])
        self.assertTrue(cancelled['detail']['worker']['confirmed_dead'])
        self.assertTrue(cancelled['confirmed_dead'])
        fresh = self.server.tool_start(form)
        self.assertNotEqual(fresh['execution_id'], execution_id)
        until_terminal(Path(fresh['record_dir']))


class StartFailureSurfaceTests(unittest.TestCase):
    """R5: failed starts keep the execution id recoverable."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix='review-startfail '))
        cls.policy, cls.policy_path = make_policy(cls.tmp, start_confirm_seconds=1)
        cls.server = server_module.Server(cls.policy_path)

    def test_unconfirmed_start_returns_id_and_serve_error(self):
        def fake_popen(command, **kwargs):
            record_dir = Path(command[command.index('--record-dir') + 1])
            common.write_new(record_dir / 'serve-error.json',
                             {'state': 'not_started', 'error': {'kind': 'Invalid', 'reason': 'boom'}})
            return object()

        with mock.patch.object(server_module.subprocess, 'Popen', fake_popen):
            result = self.server.tool_start({'operation': 'native', 'program': 'git',
                                             'workdir': str(self.tmp), 'args': ['--version']})
        self.assertEqual(result['state'], 'unconfirmed_start')
        self.assertIn('execution_id', result)
        self.assertEqual(result['serve_error']['error']['reason'], 'boom')
        # serve-error.json proves not_started (confirmed terminal): the next
        # identical start is a NEW intent, never a dead-end block; and the
        # never-created record dir must not crash cancel.
        with mock.patch.object(server_module.subprocess, 'Popen', fake_popen):
            again = self.server.tool_start({'operation': 'native', 'program': 'git',
                                            'workdir': str(self.tmp), 'args': ['--version']})
        self.assertNotEqual(again['execution_id'], result['execution_id'])
        self.assertFalse(again.get('dedup_blocked'))
        cancelled = self.server.tool_cancel({'execution_id': result['execution_id']})
        self.assertEqual(cancelled['cancel_action'], 'already_terminal')
        self.assertEqual(cancelled['state'], 'not_started')

    def test_spawn_oserror_records_failure_and_unlocks(self):
        # R5 follow-up: even a raw Popen OSError must persist a serve-error
        # tied to the id, so the next start is a new intent, not a dead end.
        with mock.patch.object(server_module.subprocess, 'Popen',
                               side_effect=OSError(193, 'bad exe')):
            result = self.server.tool_start({'operation': 'native', 'program': 'git',
                                             'workdir': str(self.tmp), 'args': ['--version']})
        self.assertEqual(result['state'], 'start_failed')
        self.assertIn('execution_id', result)
        serve_error = self.server.serve_root / result['execution_id'] / 'serve-error.json'
        self.assertTrue(serve_error.is_file())
        with mock.patch.object(server_module.subprocess, 'Popen',
                               side_effect=OSError(193, 'bad exe')):
            again = self.server.tool_start({'operation': 'native', 'program': 'git',
                                            'workdir': str(self.tmp), 'args': ['--version']})
        self.assertNotEqual(again['execution_id'], result['execution_id'])
        cancelled = self.server.tool_cancel({'execution_id': result['execution_id']})
        self.assertEqual(cancelled['cancel_action'], 'already_terminal')


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

    def test_working_roots_placeholder_expands(self):
        # '@working_roots' = inherit plus extras, without duplicating the list.
        inside = self.tmp / 'inside.txt'
        inside.write_bytes(b'data\n')
        extra_dir = Path(tempfile.mkdtemp(prefix='review-extra-root '))
        extra = extra_dir / 'extra.txt'
        extra.write_bytes(b'extra\n')
        outside = Path(tempfile.mkdtemp(prefix='review-outside-root ')) / 'out.txt'
        outside.write_bytes(b'out\n')
        self.server.policy['read_roots'] = ['@working_roots', str(extra_dir)]
        try:
            self.assertEqual(self.read(file=str(inside))['text'], 'data\n')
            self.assertEqual(self.read(file=str(extra))['text'], 'extra\n')
            with self.assertRaises(Exception) as caught:
                self.read(file=str(outside))
            self.assertIn('file_outside_read_roots', str(caught.exception))
        finally:
            self.server.policy['read_roots'] = None

    def test_utf16_be_cross_chunk_content_exact(self):
        # Review finding 2: BOM-less follow-up chunks must keep BE semantics.
        lines = ['行-%03d 中文填充内容填充内容填充内容填充内容填充填充\n' % i
                 for i in range(400)]
        content = ''.join(lines)
        path = self.tmp / 'be16.txt'
        path.write_bytes(b'\xfe\xff' + content.encode('utf-16-be'))  # >64KB, spans chunks
        self.server.policy['read_quota_bytes'] = 1048576
        try:
            result = self.read(file=str(path), max_lines=1000)
            self.assertEqual(result['encoding_used'], 'utf-16-be')
            self.assertEqual(result['text'], content)
            self.assertEqual(result['total_lines'], 400)
            self.assertFalse(result['decoding_loss'])
        finally:
            self.server.policy['read_quota_bytes'] = 200

    def test_gbk_char_split_at_chunk_boundary(self):
        # '中' lead byte lands exactly at the 65536 edge: a boundary event,
        # not a content fault (review finding 2, GBK reason variant).
        head = b'a' * 65535
        path = self.tmp / 'gbk-split.txt'
        path.write_bytes(head + '中\n'.encode('gbk') + b'second\n')
        self.server.policy['read_quota_bytes'] = 1048576
        try:
            result = self.read(file=str(path), encoding='gbk', max_lines=1000)
            self.assertNotIn('error', result)
            self.assertEqual(result['lines_served'], 2)
            self.assertEqual(result['text'], 'a' * 65535 + '中\nsecond\n')
        finally:
            self.server.policy['read_quota_bytes'] = 200

    def test_utf16_le_surrogate_split_at_boundary(self):
        head = 'a' * 32767  # 65534 bytes in utf-16-le; pair straddles the edge
        text = head + '😀\n第二行\n'
        path = self.tmp / 'le16-split.txt'
        path.write_bytes(text.encode('utf-16-le'))  # no BOM: explicit codec
        self.server.policy['read_quota_bytes'] = 1048576
        try:
            result = self.read(file=str(path), encoding='utf-16-le', max_lines=1000)
            self.assertNotIn('error', result)
            self.assertEqual(result['text'], text)
            self.assertEqual(result['lines_served'], 2)
        finally:
            self.server.policy['read_quota_bytes'] = 200

    def test_giant_single_line_aborts_before_full_accumulation(self):
        # Review finding 5: the quota must bind mid-stream, not after the
        # full line has formed.
        path = self.tmp / 'giant.txt'
        path.write_bytes(b'x' * 262144)  # quota is 200 in this class
        result = self.read(file=str(path))
        self.assertEqual(result['error'], 'single_line_exceeds_quota')
        self.assertEqual(result['line_number'], 1)
        self.assertLess(result['line_bytes_at_least'], 262144)


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


class NativeExeGuardTests(unittest.TestCase):
    """BatBadBut guard: batch files must never execute as native programs,
    even if someone registers one (V1 .exe rule restored at plan layer)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix='review-exeguard '))
        cls.policy, cls.policy_path = make_policy(cls.tmp)
        cls.policy['programs']['npm'] = {'kind': 'native',
                                         'path': r'C:\nvm4w\nodejs\npm.cmd'}
        cls.policy_path.write_text(json.dumps(cls.policy), encoding='utf-8')
        cls.server = server_module.Server(cls.policy_path)

    def test_native_cmd_rejected_at_plan(self):
        started = self.server.tool_start({'operation': 'native', 'program': 'npm',
                                          'workdir': str(self.tmp), 'args': ['--version']})
        record = Path(started['record_dir'])
        self.assertEqual(until_terminal(record), 'rejected')
        result = json.loads((record / 'result.json').read_text(encoding='utf-8'))
        self.assertIn('native_requires_exe', result['error']['reason'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
