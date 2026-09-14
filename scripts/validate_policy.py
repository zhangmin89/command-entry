"""Structural validation for a pure-beta policy file.

Used by update-policy.ps1 as the only whitelisting entry point and usable
standalone. Verifies version, required keys, program kinds and paths,
operation budgets and numeric ranges. Exits 0 with a summary, or non-zero
with the first violation.
"""
import argparse
import json
from pathlib import Path
import sys

KINDS = {'native', 'python', 'powershell', 'javascript'}
OPERATIONS = {'native', 'script', 'python_unittest'}


def validate(policy):
    problems = []

    def need(condition, message):
        if not condition:
            problems.append(message)

    need(policy.get('version') == 2, 'version must be 2')
    for key in ('python', 'powershell', 'record_root', 'serve_root', 'working_roots'):
        need(isinstance(policy.get(key), str if key in ('python', 'powershell', 'record_root', 'serve_root') else list)
             and (policy.get(key) if isinstance(policy.get(key), list) else True),
             key + '_required')
    programs = policy.get('programs', {})
    need(isinstance(programs, dict) and programs, 'programs_required')
    for name, item in programs.items():
        need(isinstance(item, dict) and item.get('kind') in KINDS and isinstance(item.get('path'), str),
             'program_invalid:' + str(name))
        need(Path(item['path']).is_file() if isinstance(item, dict) and isinstance(item.get('path'), str) else False,
             'program_path_missing:' + str(name))
        # Batch files route through cmd.exe, which re-interprets the argument
        # line — model-controlled args would escape the whitelist (BatBadBut
        # class). native programs must be real .exe files.
        if isinstance(item, dict) and item.get('kind') == 'native' and isinstance(item.get('path'), str):
            need(item['path'].lower().endswith('.exe'),
                 'native_program_must_be_exe:' + str(name))
    operations = policy.get('operations', {})
    for name in OPERATIONS:
        definition = operations.get(name, {})
        budget = definition.get('run_seconds')
        need(name in operations and type(budget) in (int, float) and 0 < budget <= 3600,
             'operation_budget_invalid:' + name)
        need(definition.get('wait_category') in ('long_task', 'process_readiness'),
             'wait_category_invalid:' + name)
    for key, low, high in (('output_quota_bytes', 256, 1048576),
                           ('read_quota_bytes', 256, 1048576),
                           ('cleanup_seconds', 0, 600),
                           ('wait_budget_seconds', 1, 300),
                           ('wait_poll_interval_seconds', 1, 60),
                           ('cancel_grace_seconds', 1, 120),
                           ('cancel_confirm_seconds', 1, 60),
                           ('claim_timeout_seconds', 10, 3600),
                           ('start_confirm_seconds', 1, 120),
                           ('wait_stop_after_no_progress', 2, 100)):
        value = policy.get(key, low)
        need(type(value) is int and low <= value <= high, key + '_out_of_range')
    need(isinstance(policy.get('require_orphan_guarantee', False), bool),
         'require_orphan_guarantee_must_be_bool')
    # R8: an explicit [] is VALID and means deny-all reads; only null/absent
    # inherits working_roots. The validator must not confuse the two.
    # '@working_roots' is the only allowed @-placeholder.
    roots = policy.get('read_roots')
    need(roots is None or (isinstance(roots, list) and all(isinstance(r, str) for r in roots)),
         'read_roots_invalid')
    if isinstance(roots, list):
        need(all(not r.startswith('@') or r == '@working_roots' for r in roots),
             'read_roots_unknown_placeholder')
    return problems


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('policy')
    options = parser.parse_args()
    try:
        policy = json.loads(Path(options.policy).read_text(encoding='utf-8-sig'))
    except (OSError, ValueError) as error:
        print(json.dumps({'valid': False, 'problems': [type(error).__name__ + ': ' + str(error)[:200]]}))
        return 1
    problems = validate(policy)
    print(json.dumps({'valid': not problems, 'problems': problems,
                      'programs': sorted(policy.get('programs', {})),
                      'working_roots': policy.get('working_roots')}, ensure_ascii=True))
    return 0 if not problems else 1


if __name__ == '__main__':
    sys.exit(main())
