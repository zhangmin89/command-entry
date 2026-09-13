"""Deny-all sentinel for the shell channel (pure beta, plan stage 3).

Negative matching: every PreToolUse call to a known shell tool is denied with
a pointer to the exec server. No shape validation, no binding reads, no
business data, no command content in records. This hook never executes tasks
and never approves permissions.

Tool-name coverage: hosts name their shell channel differently (Bash / shell
/ exec / exec_command have all been observed). The deny set is a closed list
of shell tool names; anything else passes through. When a host introduces a
new shell tool name, add it here AND in the hooks.json matcher — an
uncovered name leaves the channel silently open.
"""
import argparse
import json
from pathlib import Path
import sys
import time
import uuid

VERSION = 'pure-beta.hook-sentinel.2'
ROOT = Path(__file__).resolve().parent
SHELL_TOOLS = ('Bash', 'shell', 'exec', 'exec_command')


def handle(raw):
    """Return (answer, meta). Deny-closed: unparseable events are denied too."""
    started = time.perf_counter()
    try:
        event = json.loads(raw)
        if not isinstance(event, dict):
            raise ValueError('event_object_required')
    except ValueError:
        event, route = {}, 'invalid_event_denied'
    else:
        route = 'outside_matcher'
        if event.get('hook_event_name') == 'PreToolUse' and event.get('tool_name') in SHELL_TOOLS:
            route = 'shell_denied'
    if route != 'outside_matcher':
        answer = {'hookSpecificOutput': {'hookEventName': 'PreToolUse',
                 'permissionDecision': 'deny',
                 'permissionDecisionReason':
                     'The shell channel is closed (pure beta). Use the exec server tools: '
                     'start_operation / status / output / cancel / wait / read_text. '
                     'Out-of-policy needs follow the exception process, not raw shell. '
                     'This hook never executes tasks or approves permissions.'}}
    else:
        answer = {}
    meta = {'id': str(uuid.uuid4()), 'version': VERSION, 'route': route,
            'session_id': event.get('session_id'), 'tool_use_id': event.get('tool_use_id'),
            'tool_name': event.get('tool_name'),
            'decision': 'deny' if answer else 'passthrough',
            'elapsed_seconds': time.perf_counter() - started, 'timestamp': time.time()}
    return answer, meta


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--records', default=str(ROOT / 'hook-records'))
    options = parser.parse_args()
    answer, meta = handle(sys.stdin.read())
    try:
        logs = Path(options.records)
        logs.mkdir(parents=True, exist_ok=True)
        # Envelope only: ids, route and timing; the command itself is never stored.
        with (logs / (meta['id'] + '.json')).open('x', encoding='utf-8') as stream:
            json.dump(meta, stream, ensure_ascii=True)
    except OSError:
        answer = dict(answer, systemMessage='Command entry sentinel record was not persisted; no additional permissions were requested.')
    print(json.dumps(answer, ensure_ascii=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
