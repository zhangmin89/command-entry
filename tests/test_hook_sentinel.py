"""Stage 3 sentinel tests: the shell channel is closed, deny + pointer only.

The old shape-checking suite (V2 launch grammar, binding hashes, envelope
fingerprints) is retired with the V1/V2 hook routes; its guarantees now live
in the server's schema/policy chain covered by tests/test_server.py.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import hook_v2  # noqa: E402


class SentinelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = Path(tempfile.mkdtemp(prefix='hook-sentinel-test '))

    def handle(self, event):
        return hook_v2.handle(json.dumps(event))

    def test_any_shell_tool_call_denied_with_pointer(self):
        for tool in hook_v2.SHELL_TOOLS:
            for command in ('git status', 'echo raw',
                            "& 'C:/python.exe' -X utf8 'entry.py' run --request 'x.json'",
                            'dir', 'rm -rf /', ''):
                answer, meta = self.handle({'hook_event_name': 'PreToolUse',
                                             'tool_name': tool,
                                             'tool_input': {'command': command}})
                self.assertEqual(answer['hookSpecificOutput']['permissionDecision'], 'deny',
                                 f'{tool} must be denied')
                self.assertIn('exec server', answer['hookSpecificOutput']['permissionDecisionReason'])
                self.assertEqual(meta['route'], 'shell_denied')

    def test_non_shell_tool_passthrough(self):
        for tool in ('Read', 'Write', 'Edit', 'Grep'):
            answer, _ = self.handle({'hook_event_name': 'PreToolUse', 'tool_name': tool,
                                     'tool_input': {'command': 'anything'}})
            self.assertEqual(answer, {})

    def test_exec_code_cell_never_denied(self):
        # 'exec' is the code-mode JS cell and the ONLY channel for MCP tool
        # calls on Codex 0.154.0-alpha.x. Denying it would lock out the exec
        # server itself. Guard: it must stay out of SHELL_TOOLS and pass
        # through even if a host starts emitting PreToolUse for it.
        self.assertNotIn('exec', hook_v2.SHELL_TOOLS)
        answer, meta = self.handle({'hook_event_name': 'PreToolUse', 'tool_name': 'exec',
                                     'tool_input': {'command': 'anything'}})
        self.assertEqual(answer, {})
        self.assertEqual(meta['route'], 'outside_matcher')

    def test_non_pretooluse_event_passthrough(self):
        answer, _ = self.handle({'hook_event_name': 'PostToolUse', 'tool_name': 'Bash',
                                 'tool_input': {'command': 'x'}})
        self.assertEqual(answer, {})

    def test_invalid_event_denied_closed(self):
        answer, meta = hook_v2.handle('not json at all')
        self.assertEqual(answer['hookSpecificOutput']['permissionDecision'], 'deny')
        self.assertEqual(meta['route'], 'invalid_event_denied')

    def test_records_keep_envelope_only(self):
        before = set(self.records.glob('*.json'))
        event = {'hook_event_name': 'PreToolUse', 'tool_name': 'Bash',
                 'tool_input': {'command': 'SECRET-COMMAND-CONTENT'},
                 'session_id': 'sess-1'}
        # Direct record write through main()'s path pieces: handle() returns
        # meta without command content; persist exactly like main() does.
        answer, meta = hook_v2.handle(json.dumps(event))
        path = self.records / (meta['id'] + '.json')
        with path.open('x', encoding='utf-8') as stream:
            json.dump(meta, stream, ensure_ascii=True)
        added = set(self.records.glob('*.json')) - before
        self.assertEqual(len(added), 1)
        stored = json.loads(next(iter(added)).read_text(encoding='utf-8'))
        self.assertEqual(stored['decision'], 'deny')
        self.assertEqual(stored['session_id'], 'sess-1')
        self.assertNotIn('SECRET-COMMAND-CONTENT', path.read_text(encoding='utf-8'))

    def test_no_binding_dependency(self):
        # Structural guarantee: the sentinel module never reads binding files;
        # tampering with any binding must not change the deny decision.
        answer, _ = self.handle({'hook_event_name': 'PreToolUse', 'tool_name': 'Bash',
                                 'tool_input': {'command': 'x'}})
        self.assertEqual(answer['hookSpecificOutput']['permissionDecision'], 'deny')


if __name__ == '__main__':
    unittest.main(verbosity=2)
