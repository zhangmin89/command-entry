"""Stage 5 tests: policy validation, server startup self-check against the
binding anchor, envelope-only event logging, metrics collection, and the
update-policy.ps1 whitelisting entry point (real PowerShell smoke)."""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))

import build_binding  # noqa: E402
import server as server_module  # noqa: E402
import validate_policy  # noqa: E402


def base_policy(**overrides):
    policy = {
        'version': 2,
        'python': sys.executable,
        'powershell': r'C:\Program Files\PowerShell\7\pwsh.exe',
        'working_roots': [r'C:\Code'],
        'record_root': '.codex-command-records',
        'serve_root': str(Path(tempfile.mkdtemp(prefix='stage5-serve '))),
        'programs': {'python': {'kind': 'python', 'path': sys.executable}},
        'operations': {'native': {'acceptable_exit_codes': [0], 'run_seconds': 60,
                                  'wait_category': 'long_task'},
                       'script': {'acceptable_exit_codes': [0], 'run_seconds': 60,
                                  'wait_category': 'long_task'},
                       'python_unittest': {'acceptable_exit_codes': [0], 'run_seconds': 60,
                                           'wait_category': 'long_task'}},
        'output_quota_bytes': 65536,
        'read_quota_bytes': 65536,
        'cleanup_seconds': 10,
        'wait_budget_seconds': 30,
        'wait_poll_interval_seconds': 5,
        'cancel_grace_seconds': 15,
        'require_orphan_guarantee': False,
    }
    policy.update(overrides)
    return policy


class ValidatePolicyTests(unittest.TestCase):
    def test_template_policy_valid(self):
        self.assertEqual(validate_policy.validate(base_policy()), [])

    def test_bad_policies_rejected(self):
        problems = validate_policy.validate(base_policy(version=1))
        self.assertTrue(problems)
        problems = validate_policy.validate(base_policy(
            programs={'ghost': {'kind': 'native', 'path': r'X:\missing.exe'}}))
        self.assertTrue(any('program_path_missing' in p for p in problems))
        problems = validate_policy.validate(base_policy(
            operations={'native': {'run_seconds': 0}}))
        self.assertTrue(any('operation_budget_invalid' in p for p in problems))
        problems = validate_policy.validate(base_policy(wait_budget_seconds=99999))
        self.assertTrue(any('wait_budget_seconds' in p for p in problems))


class SelfCheckTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='stage5-selfcheck '))
        self.policy_path = self.tmp / 'policy.json'
        self.policy_path.write_text(json.dumps(base_policy()), encoding='utf-8')
        self.binding_path = self.tmp / 'binding.json'
        build_binding.build(self.policy_path, self.binding_path)

    def test_matching_binding_starts(self):
        instance = server_module.Server(self.policy_path, self.binding_path)
        self.assertTrue(instance.orphan_guaranteed in (True, False))
        events = (instance.log_root / 'server-events.jsonl').read_text(encoding='utf-8')
        self.assertIn('"kind": "startup"', events)

    def test_tampered_policy_refused(self):
        self.policy_path.write_text(json.dumps(base_policy(read_quota_bytes=4096)), encoding='utf-8')
        with self.assertRaises(Exception) as caught:
            server_module.Server(self.policy_path, self.binding_path)
        self.assertIn('policy_changed_since_review', str(caught.exception))

    def test_tampered_runtime_refused(self):
        binding = json.loads(self.binding_path.read_text(encoding='utf-8'))
        binding['runtime_files'][0]['sha256'] = '0' * 64
        self.binding_path.write_text(json.dumps(binding), encoding='utf-8')
        with self.assertRaises(Exception) as caught:
            server_module.Server(self.policy_path, self.binding_path)
        self.assertIn('runtime_changed_since_review', str(caught.exception))


class MetricsTests(unittest.TestCase):
    def test_collect_from_envelopes(self):
        tmp = Path(tempfile.mkdtemp(prefix='stage5-metrics '))
        records = tmp / 'hook-records'
        records.mkdir()
        for index, route in enumerate(('shell_denied', 'shell_denied', 'invalid_event_denied', 'outside_matcher')):
            (records / (str(index) + '-' + route + '.json')).write_text(json.dumps({'route': route}), encoding='utf-8')
        serve = tmp / 'serve'
        (serve / 'exec-1').mkdir(parents=True)
        (serve / 'exec-1' / 'request.json').write_text('{}', encoding='utf-8')
        events = tmp / 'server-events.jsonl'
        lines = [
            {'kind': 'startup', 'ts': 1},
            {'kind': 'startup', 'ts': 2},
            {'kind': 'start_operation', 'dedup': True, 'retry': False},
            {'kind': 'start_operation', 'dedup': False, 'retry': True},
            {'kind': 'rejected', 'tool': 'start_operation', 'reason': 'Invalid'},
        ]
        events.write_text('\n'.join(json.dumps(line) for line in lines), encoding='utf-8')
        import collect_metrics
        result = collect_metrics.collect(records, events, serve)
        self.assertEqual(result['hook']['shell_denied'], 2)
        self.assertEqual(result['hook']['deny_rate'], 0.75)
        self.assertEqual(result['server']['startup_events'], 2)
        self.assertEqual(result['server']['in_flight_dedup_hits'], 1)
        self.assertEqual(result['server']['retries'], 1)
        self.assertEqual(result['executions']['serve_inputs'], 1)


class UpdatePolicySmoke(unittest.TestCase):
    def make_repo(self, prefix):
        tmp = Path(tempfile.mkdtemp(prefix=prefix))
        repo = tmp / 'repo'
        repo.mkdir()
        for name in build_binding.RUNTIME_FILES:
            shutil.copy(ROOT / name, repo / name)
        (repo / 'scripts').mkdir()
        shutil.copy(ROOT / 'scripts' / 'build_binding.py', repo / 'scripts' / 'build_binding.py')
        shutil.copy(ROOT / 'scripts' / 'validate_policy.py', repo / 'scripts' / 'validate_policy.py')
        shutil.copy(ROOT / 'update-policy.ps1', repo / 'update-policy.ps1')
        policy = base_policy(serve_root=str(tmp / 'serve'))
        (repo / 'policy.json').write_text(json.dumps(policy), encoding='utf-8')
        subprocess.run([sys.executable, '-X', 'utf8', str(repo / 'scripts' / 'build_binding.py'),
                        '--policy', str(repo / 'policy.json'), '--out', str(repo / 'binding.json')],
                       check=True, capture_output=True)
        return repo

    def hashes(self, repo):
        import hashlib
        return {name: hashlib.sha256((repo / name).read_bytes()).hexdigest()
                for name in ('policy.json', 'binding.json')}

    def test_add_program_repins_binding(self):
        repo = self.make_repo('stage5-updatepolicy ')
        completed = subprocess.run(
            ['pwsh', '-NoProfile', '-File', str(repo / 'update-policy.ps1'),
             '-RepoRoot', str(repo), '-AddProgram', 'git',
             '-ProgramPath', r'C:\Program Files\Git\cmd\git.exe', '-Kind', 'native'],
            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=120)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        updated = json.loads((repo / 'policy.json').read_text(encoding='utf-8'))
        self.assertIn('git', updated['programs'])
        binding = json.loads((repo / 'binding.json').read_text(encoding='utf-8'))
        self.assertEqual(binding['schema_version'], 2)
        # The freshly pinned server must start against the new anchor.
        instance = server_module.Server(repo / 'policy.json', repo / 'binding.json')
        self.assertIn('git', instance.policy['programs'])

    def test_missing_program_path_leaves_live_pair_untouched(self):
        # R4: pre-commit failure must not touch policy.json/binding.json.
        repo = self.make_repo('stage5-policy-fail-path ')
        before = self.hashes(repo)
        completed = subprocess.run(
            ['pwsh', '-NoProfile', '-File', str(repo / 'update-policy.ps1'),
             '-RepoRoot', str(repo), '-AddProgram', 'ghost',
             '-ProgramPath', r'X:\definitely-missing.exe', '-Kind', 'native'],
            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=120)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(self.hashes(repo), before)

    def test_invalid_candidate_leaves_live_pair_untouched(self):
        # R4: validation failure happens before any live write or backup.
        repo = self.make_repo('stage5-policy-fail-validate ')
        before = self.hashes(repo)
        candidate = repo.parent / 'bad-candidate.json'
        bad = base_policy(serve_root=str(repo.parent / 'serve'),
                          operations={'native': {'run_seconds': 0}})
        candidate.write_text(json.dumps(bad), encoding='utf-8')
        completed = subprocess.run(
            ['pwsh', '-NoProfile', '-File', str(repo / 'update-policy.ps1'),
             '-RepoRoot', str(repo), '-PolicyPath', str(candidate)],
            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=120)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn('validation failed', completed.stdout + completed.stderr)
        self.assertEqual(self.hashes(repo), before)


if __name__ == '__main__':
    unittest.main(verbosity=2)
