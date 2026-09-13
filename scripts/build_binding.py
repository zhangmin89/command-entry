"""Build binding.json: the integrity anchor for the server file set + policy.

Stage 3 re-pins the binding to the pure-beta object set: the legacy V1 entry
route and the V2 launch grammar are dropped; the hook no longer consumes the
binding at all. The only consumer is the server startup self-check (stage 5).

Usage: python scripts/build_binding.py --policy <policy.json> [--out binding.json]
"""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNTIME_FILES = ('server.py', 'common.py', 'entry_v2.py', 'worker_v2.py',
                 'windows_state.py', 'wait_state.py', 'adapter.py',
                 'output_store.py', 'v1_support.py', 'invoke.ps1',
                 'check_python.py', 'check_powershell.ps1')


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def build(policy_path, output_path):
    policy_path = Path(policy_path).resolve()
    binding = {
        'schema_version': 2,
        'phase': 'pure_beta_stage3',
        'policy': {'path': str(policy_path), 'sha256': sha256(policy_path)},
        'runtime_files': [{'path': str(ROOT / name), 'sha256': sha256(ROOT / name)}
                          for name in RUNTIME_FILES],
    }
    Path(output_path).write_text(json.dumps(binding, indent=2, ensure_ascii=True),
                                 encoding='utf-8')
    return binding


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--policy', default=str(ROOT / 'policy.json'))
    parser.add_argument('--out', default=str(ROOT / 'binding.json'))
    options = parser.parse_args()
    binding = build(options.policy, options.out)
    print(json.dumps({'written': options.out, 'files': len(binding['runtime_files']),
                      'policy_sha256': binding['policy']['sha256']}, ensure_ascii=True))
