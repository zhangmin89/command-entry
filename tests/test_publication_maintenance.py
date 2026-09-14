"""Run the maintenance script against disposable installs, never the live one."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from scripts import build_binding
from tests.test_review_fixes import make_policy

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / 'scripts' / 'apply-publication-maintenance.ps1'
IDENTITIES = {
    '32ee416c-7ed3-532e-856c-3ff84f09a257': 'da09a52adc587ee5b30ade57750bb9dcf12075e9ed7c188955db5d265705766c',
    'b6e13d59-0a85-5f3b-be87-3c4d22743647': 'd060a957baea03c74fec260aa905813b6a23cdede4318e4ceaf66e1ba0a28ace',
    '0b25593f-66dc-5deb-84f7-745e23a40692': 'c0e95ed5888ac9bac76d9fc69dda3f37d3ca3f544cc4473241208d5512db19a8',
}


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='publication-maintenance '))
        self.install = self.tmp / 'install'
        self.install.mkdir()
        for name in build_binding.RUNTIME_FILES:
            shutil.copyfile(ROOT / name, self.install / name)
        for name in ('server.py', 'entry_v2.py'):
            with (self.install / name).open('a', encoding='utf-8') as stream:
                stream.write('\n# Previous deployed fixture.\n')
        self.old_runtime = {name: (self.install / name).read_bytes()
                            for name in ('server.py', 'entry_v2.py')}
        (self.install / 'scripts').mkdir()
        for name in ('build_binding.py', 'validate_policy.py'):
            shutil.copyfile(ROOT / 'scripts' / name, self.install / 'scripts' / name)
        policy, policy_path = make_policy(self.tmp, serve_root=str(self.install / 'serve-input'),
                                         read_quota_bytes=65536)
        policy['powershell'] = r'C:\Program Files\PowerShell\7\pwsh.exe'
        policy['operations']['python_unittest'] = dict(policy['operations']['native'])
        self.policy_path = self.install / 'policy.json'
        self.policy_path.write_text(json.dumps(policy), encoding='utf-8')
        self.policy_bytes = self.policy_path.read_bytes()
        self.binding_path = self.install / 'binding.json'
        with mock.patch.object(build_binding, 'ROOT', self.install):
            build_binding.build(self.policy_path, self.binding_path)
        self.binding_bytes = self.binding_path.read_bytes()
        self.serve = self.install / 'serve-input'
        self.requests = {}
        for identity, fingerprint in IDENTITIES.items():
            directory = self.serve / identity
            directory.mkdir(parents=True)
            content = json.dumps({'content_fingerprint': fingerprint,
                                  'business': {'cwd': str(self.tmp)}}).encode('utf-8')
            (directory / 'request.json').write_bytes(content)
            self.requests[identity] = content
        self.backup = self.install / 'maintenance' / 'publication-fixes-20260914'
        self.quarantine = self.install / 'quarantine' / 'half-published-20260914'

    def invoke(self, apply=False):
        command = ['pwsh', '-NoProfile', '-File', str(SCRIPT),
                   '-InstallRoot', str(self.install), '-SourceRoot', str(ROOT)]
        if apply:
            command.append('-Apply')
        return subprocess.run(command, capture_output=True, timeout=60,
                              creationflags=subprocess.CREATE_NO_WINDOW)

    def assert_live_unchanged(self):
        self.assertEqual(self.policy_path.read_bytes(), self.policy_bytes)
        self.assertEqual(self.binding_path.read_bytes(), self.binding_bytes)
        for name, content in self.old_runtime.items():
            self.assertEqual((self.install / name).read_bytes(), content)
        for identity, content in self.requests.items():
            self.assertEqual((self.serve / identity / 'request.json').read_bytes(), content)
        self.assertFalse(self.backup.exists())

    def test_preview_does_not_change_install_or_records(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        plan = json.loads(result.stdout)
        self.assertFalse(plan['apply'])
        self.assertEqual(len(plan['copies']), 2)
        self.assertEqual(len(plan['moves']), 3)
        self.assert_live_unchanged()
        self.assertFalse(self.quarantine.exists())

    def test_apply_preserves_history_backs_up_runtime_and_repins_unchanged_policy(self):
        result = self.invoke(apply=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.policy_path.read_bytes(), self.policy_bytes)
        self.assertEqual((self.backup / 'binding.json').read_bytes(), self.binding_bytes)
        for name, content in self.old_runtime.items():
            self.assertEqual((self.backup / name).read_bytes(), content)
            self.assertEqual((self.install / name).read_bytes(), (ROOT / name).read_bytes())
        for identity, content in self.requests.items():
            self.assertFalse((self.serve / identity).exists())
            self.assertEqual((self.quarantine / identity / 'request.json').read_bytes(), content)
        binding = json.loads(self.binding_path.read_text(encoding='utf-8'))
        self.assertEqual(binding['policy']['sha256'], hashlib.sha256(self.policy_bytes).hexdigest())
        for item in binding['runtime_files']:
            self.assertEqual(item['sha256'], hashlib.sha256(Path(item['path']).read_bytes()).hexdigest())
        manifest = json.loads((self.backup / 'manifest.json').read_text(encoding='utf-8'))
        self.assertEqual(len(manifest['moves']), 3)

    def test_existing_quarantine_is_not_overwritten(self):
        self.quarantine.mkdir(parents=True)
        marker = self.quarantine / 'keep.txt'
        marker.write_bytes(b'existing quarantine')
        result = self.invoke(apply=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'Maintenance target already exists', result.stderr)
        self.assertEqual(marker.read_bytes(), b'existing quarantine')
        self.assert_live_unchanged()

    def test_new_claim_prevents_all_mutations(self):
        identity, fingerprint = next(iter(IDENTITIES.items()))
        claim = self.serve / '_claims' / fingerprint / 'claim.json'
        claim.parent.mkdir(parents=True)
        claim.write_text(json.dumps({'execution_id': identity}), encoding='utf-8')
        result = self.invoke(apply=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'Execution or claim now exists', result.stderr)
        self.assert_live_unchanged()

    def test_running_server_prevents_all_mutations(self):
        process = subprocess.Popen([sys.executable, '-X', 'utf8', str(self.install / 'server.py'),
                                    '--policy', str(self.policy_path), '--binding', str(self.binding_path)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            result = self.invoke(apply=True)
            self.assertIsNone(process.poll())
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'Stop the listed command-entry servers and children', result.stderr)
            self.assert_live_unchanged()
        finally:
            process.terminate()
            process.communicate(timeout=10)
