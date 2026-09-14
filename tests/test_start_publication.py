"""Publication failures, corrupt history, policy snapshots and dotnet diagnostics."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import common
import entry_v2
import server
from scripts import build_binding
from tests.test_review_fixes import make_policy


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='publication-regression '))
        self.policy, self.policy_path = make_policy(self.tmp)
        self.instance = server.Server(self.policy_path)
        self.form = {'operation': 'native', 'program': 'git',
                     'workdir': str(self.tmp), 'args': ['--version']}

    def finish_start(self, command, **kwargs):
        serve_dir = Path(command[command.index('--record-dir') + 1])
        record = self.tmp / '.codex-command-records' / serve_dir.name
        record.mkdir(parents=True)
        common.write_new(record / 'result.json', {'state': 'exited',
                                                 'execution_id': serve_dir.name})
        return object()

    def test_each_publication_failure_is_queryable_and_next_intent_can_start(self):
        for failed_name in ('request.json', 'policy.json', 'claim.json'):
            with self.subTest(failed_name=failed_name):
                form = dict(self.form, args=[failed_name])
                original_write = server.write_new
                original_save = server.save

                def write(path, value):
                    if Path(path).name == failed_name:
                        Path(path).write_bytes(b'{')
                        raise OSError('injected publication write failure')
                    return original_write(path, value)

                def save(path, value):
                    if Path(path).name == failed_name == 'claim.json':
                        raise OSError('injected claim publication failure')
                    return original_save(path, value)

                with mock.patch.object(server, 'write_new', write), \
                        mock.patch.object(server, 'save', save), \
                        mock.patch.object(server.subprocess, 'Popen') as spawn:
                    failed = self.instance.tool_start(form)
                spawn.assert_not_called()
                self.assertEqual(failed['state'], 'start_failed')
                queried = self.instance.tool_status({'execution_id': failed['execution_id']})
                self.assertEqual(queried['state'], 'start_failed')
                self.assertIn(failed_name, queried['serve_error']['error']['reason'])
                self.assertEqual(queried['serve_error']['state'], 'not_started')
                self.assertFalse(Path(failed['record_dir']).exists())
                with mock.patch.object(server.subprocess, 'Popen', self.finish_start):
                    fresh = self.instance.tool_start(form)
                self.assertNotEqual(fresh['execution_id'], failed['execution_id'])
                self.assertFalse(fresh.get('dedup_blocked'))

    def test_corrupt_unrelated_history_does_not_block_start_and_logs_path(self):
        corrupt = self.instance.serve_root / '22222222-2222-4222-8222-222222222222'
        corrupt.mkdir()
        for data in ('{', '[]'):
            with self.subTest(data=data):
                request = corrupt / 'request.json'
                request.write_text(data, encoding='utf-8')
                with mock.patch.object(server.subprocess, 'Popen', self.finish_start):
                    started = self.instance.tool_start(self.form)
                self.assertEqual(self.instance.tool_status(
                    {'execution_id': started['execution_id']})['state'], 'exited')
                events = [json.loads(line) for line in
                          (self.instance.log_root / 'server-events.jsonl').read_text(
                              encoding='utf-8').splitlines()]
                errors = [event for event in events if event['kind'] == 'request_record_unreadable']
                self.assertTrue(any(event['file'] == str(request) for event in errors))
                self.assertEqual(request.read_text(encoding='utf-8'), data)

    def test_corrupt_claim_target_fails_closed_with_its_path(self):
        with mock.patch.object(server.subprocess, 'Popen', self.finish_start):
            first = self.instance.tool_start(self.form)
        request = self.instance.serve_root / first['execution_id'] / 'request.json'
        request.write_text('{', encoding='utf-8')
        with mock.patch.object(server.subprocess, 'Popen') as spawn:
            with self.assertRaises(common.Invalid) as caught:
                self.instance.tool_start(self.form)
        spawn.assert_not_called()
        self.assertIn(str(request), str(caught.exception))

    def test_corrupt_request_without_claim_does_not_reuse_occupied_identity(self):
        with mock.patch.object(server.subprocess, 'Popen', self.finish_start):
            first = self.instance.tool_start(self.form)
        request = self.instance.serve_root / first['execution_id'] / 'request.json'
        fingerprint = common.read_json(request)['content_fingerprint']
        request.write_text('{', encoding='utf-8')
        (self.instance.serve_root / '_claims' / fingerprint / 'claim.json').unlink()
        with mock.patch.object(server.subprocess, 'Popen') as spawn:
            with self.assertRaises(common.Invalid):
                self.instance.tool_start(self.form)
        spawn.assert_not_called()
        self.assertEqual(request.read_text(encoding='utf-8'), '{')

    def test_half_published_history_without_marker_remains_blocked(self):
        with mock.patch.object(server.subprocess, 'Popen', self.finish_start):
            first = self.instance.tool_start(self.form)
        serve_dir = self.instance.serve_root / first['execution_id']
        fingerprint = common.read_json(serve_dir / 'request.json')['content_fingerprint']
        (serve_dir / 'policy.json').unlink()
        record = Path(first['record_dir'])
        (record / 'result.json').unlink()
        record.rmdir()
        (self.instance.serve_root / '_claims' / fingerprint / 'claim.json').unlink()
        with mock.patch.object(server.subprocess, 'Popen') as spawn:
            blocked = self.instance.tool_start(self.form)
        spawn.assert_not_called()
        self.assertEqual(blocked['execution_id'], first['execution_id'])
        self.assertTrue(blocked['dedup_blocked'])

    def test_policy_change_after_binding_check_is_rejected_before_publication(self):
        binding = self.tmp / 'binding.json'
        build_binding.build(self.policy_path, binding)
        instance = server.Server(self.policy_path, binding)
        for changed in (dict(self.policy, read_quota_bytes=300), None):
            with self.subTest(changed=changed is not None):
                self.policy_path.write_text(json.dumps(changed) if changed else '{', encoding='utf-8')
                with mock.patch.object(server.subprocess, 'Popen') as spawn:
                    with self.assertRaisesRegex(common.Invalid, 'policy_changed_since_review'):
                        instance.tool_start(self.form)
                spawn.assert_not_called()
                self.assertEqual(list(instance.serve_root.iterdir()), [])

    def test_policy_snapshot_uses_the_bytes_checked_for_this_call(self):
        original = server.write_new
        changed = dict(self.policy, read_quota_bytes=999)

        def change_after_request(path, value):
            result = original(path, value)
            if Path(path).name == 'request.json':
                common.save(self.policy_path, changed)
            return result

        with mock.patch.object(server, 'write_new', change_after_request), \
                mock.patch.object(server.subprocess, 'Popen', self.finish_start):
            first = self.instance.tool_start(self.form)
        snapshot = common.read_json(self.instance.serve_root / first['execution_id'] / 'policy.json')
        self.assertEqual(snapshot, self.policy)
        with mock.patch.object(server.subprocess, 'Popen') as spawn:
            with self.assertRaisesRegex(common.Invalid, 'policy_changed_since_review'):
                self.instance.tool_start(self.form)
        spawn.assert_not_called()


class CorruptClaimTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='corrupt-claim '))
        _, self.policy_path = make_policy(self.tmp)
        self.instance = server.Server(self.policy_path)
        self.form = {'operation': 'native', 'program': 'git',
                     'workdir': str(self.tmp), 'args': ['--version']}
        self.fingerprint = common.digest(self.form)
        self.claim_dir = self.instance.serve_root / '_claims' / self.fingerprint
        self.claim_dir.mkdir(parents=True)
        self.claim_file = self.claim_dir / 'claim.json'

    def publish(self):
        with mock.patch.object(server.subprocess, 'Popen', self.finish_start):
            return self.instance.tool_start(self.form)

    def finish_start(self, command, **kwargs):
        serve_dir = Path(command[command.index('--record-dir') + 1])
        record = self.tmp / '.codex-command-records' / serve_dir.name
        record.mkdir(parents=True)
        common.write_new(record / 'result.json', {'state': 'exited',
                                                 'execution_id': serve_dir.name})
        return object()

    def test_invalid_claim_heals_to_same_running_or_unknown_execution(self):
        first = self.publish()
        for data in ('{', '[]', '{}', '{"execution_id": 7}',
                     '{"execution_id": "../outside"}'):
            for state in ('running', 'unknown'):
                with self.subTest(data=data, state=state):
                    self.claim_file.write_text(data, encoding='utf-8')
                    with mock.patch.object(self.instance, 'snapshot', return_value={'state': state}), \
                            mock.patch.object(server.subprocess, 'Popen') as spawn:
                        result = self.instance.tool_start(self.form)
                    spawn.assert_not_called()
                    self.assertEqual(result['execution_id'], first['execution_id'])
                    self.assertEqual(result['in_flight_dedup'], state == 'running')
                    self.assertEqual(result['dedup_blocked'], state == 'unknown')
                    self.assertEqual(common.read_json(self.claim_file)['execution_id'],
                                     first['execution_id'])
        events = [json.loads(line) for line in
                  (self.instance.log_root / 'server-events.jsonl').read_text(
                      encoding='utf-8').splitlines()]
        errors = [event for event in events if event['kind'] == 'claim_record_unreadable']
        self.assertEqual(len(errors), 10)
        self.assertTrue(all(event['file'] == str(self.claim_file) for event in errors))

    def test_invalid_claim_without_identity_fails_with_path_and_keeps_evidence(self):
        self.claim_file.write_text('{', encoding='utf-8')
        with mock.patch.object(server.subprocess, 'Popen') as spawn:
            with self.assertRaises(common.Invalid) as caught:
                self.instance.tool_start(self.form)
        spawn.assert_not_called()
        self.assertIn(str(self.claim_file), str(caught.exception))
        self.assertEqual(self.claim_file.read_text(encoding='utf-8'), '{')

    def test_invalid_claim_does_not_fall_back_to_old_terminal_when_history_is_corrupt(self):
        first = self.publish()
        second = self.publish()
        request = self.instance.serve_root / second['execution_id'] / 'request.json'
        self.assertNotEqual(first['execution_id'], second['execution_id'])
        for data in ('{', '[]', '{}'):
            with self.subTest(data=data):
                request.write_text(data, encoding='utf-8')
                self.claim_file.write_text('{', encoding='utf-8')
                with mock.patch.object(server.subprocess, 'Popen') as spawn:
                    with self.assertRaises(common.Invalid) as caught:
                        self.instance.tool_start(self.form)
                spawn.assert_not_called()
                self.assertIn(str(self.claim_file), str(caught.exception))
                self.assertIn(str(request), str(caught.exception))
                self.assertEqual(self.claim_file.read_text(encoding='utf-8'), '{')

    def test_claim_io_failure_is_not_treated_as_absence(self):
        self.publish()
        original = server.read_json

        def read(path):
            if Path(path) == self.claim_file:
                raise PermissionError('injected claim read failure')
            return original(path)

        before = self.claim_file.read_bytes()
        with mock.patch.object(server, 'read_json', read), \
                mock.patch.object(server.subprocess, 'Popen') as spawn:
            with self.assertRaises(common.Invalid) as caught:
                self.instance.tool_start(self.form)
        spawn.assert_not_called()
        self.assertIn(str(self.claim_file), str(caught.exception))
        self.assertIsInstance(caught.exception.__cause__, PermissionError)
        self.assertEqual(self.claim_file.read_bytes(), before)

    def test_with_body_errors_propagate_unchanged_and_release_lock(self):
        first = self.publish()
        for corrupt in (False, True):
            for error in (common.Invalid('caller invalid'), ValueError('caller value'),
                          OSError('caller io')):
                with self.subTest(corrupt=corrupt, error=type(error).__name__):
                    if corrupt:
                        self.claim_file.write_text('{', encoding='utf-8')
                    with self.assertRaises(type(error)) as caught:
                        with self.instance.claim_section(self.fingerprint) as claim:
                            self.assertEqual(claim[:2], ('existing', first['execution_id']))
                            raise error
                    self.assertIs(caught.exception, error)
                    other = server.Server(self.policy_path)
                    with other.claim_section(self.fingerprint) as claim:
                        self.assertEqual(claim[:2], ('existing', first['execution_id']))

    def test_heal_write_failure_has_path_and_does_not_enter_body(self):
        self.publish()
        self.claim_file.write_text('{', encoding='utf-8')
        with mock.patch.object(server, 'save', side_effect=OSError('injected heal failure')):
            with self.assertRaises(common.Invalid) as caught:
                with self.instance.claim_section(self.fingerprint):
                    self.fail('Claim body must not run after failed healing')
        self.assertIn(str(self.claim_file), str(caught.exception))
        self.assertEqual(self.claim_file.read_text(encoding='utf-8'), '{')
        with self.instance.claim_section(self.fingerprint) as claim:
            self.assertEqual(claim[0], 'existing')


class DotnetEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='dotnet-environment '))
        self.policy, _ = make_policy(self.tmp)
        self.dotnet = self.tmp / 'dotnet.exe'
        self.dotnet.write_bytes(b'plan-only fixture; never executed')
        self.policy['programs']['dotnet'] = {'kind': 'native', 'path': str(self.dotnet)}
        self.req = {'operation': 'native', 'program': 'dotnet', 'args': ['--info']}

    def test_missing_architecture_rejects_info_without_changing_environment(self):
        environment = dict(os.environ)
        environment.pop('PROCESSOR_ARCHITECTURE', None)
        with mock.patch.dict(os.environ, environment, clear=True):
            with self.assertRaisesRegex(common.Invalid, 'dotnet_environment_missing: PROCESSOR_ARCHITECTURE'):
                entry_v2.plan(self.req, self.policy, mock.Mock(), self.tmp)
            self.assertNotIn('PROCESSOR_ARCHITECTURE', os.environ)

    def test_present_architecture_allows_info(self):
        with mock.patch.dict(os.environ, {'PROCESSOR_ARCHITECTURE': 'AMD64'}):
            argv, _, _ = entry_v2.plan(self.req, self.policy, mock.Mock(), self.tmp)
        self.assertEqual(argv, [str(self.dotnet), '--info'])

    def test_missing_architecture_does_not_reject_other_native_commands(self):
        environment = dict(os.environ)
        environment.pop('PROCESSOR_ARCHITECTURE', None)
        with mock.patch.dict(os.environ, environment, clear=True):
            argv, _, _ = entry_v2.plan(dict(self.req, args=['--version']),
                                      self.policy, mock.Mock(), self.tmp)
            git, _, _ = entry_v2.plan({'operation': 'native', 'program': 'git', 'args': ['--version']},
                                     self.policy, mock.Mock(), self.tmp)
        self.assertEqual(argv, [str(self.dotnet), '--version'])
        self.assertEqual(git[1:], ['--version'])

    def test_application_info_argument_is_not_a_dotnet_cli_environment_check(self):
        environment = dict(os.environ)
        environment.pop('PROCESSOR_ARCHITECTURE', None)
        with mock.patch.dict(os.environ, environment, clear=True):
            argv, _, _ = entry_v2.plan(dict(self.req, args=['app.dll', '--info']),
                                      self.policy, mock.Mock(), self.tmp)
        self.assertEqual(argv, [str(self.dotnet), 'app.dll', '--info'])
