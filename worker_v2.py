"""One immutable execution plan, received only after the owner assigns its Job.

Calling convention only, not a security guarantee: the plan on stdin is
trusted input from the owning entry process. This module performs no
independent validation of the plan and must never be run directly against
untrusted input.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
from common import save
from windows_state import observe


def main():
    plan = json.loads(sys.stdin.buffer.readline())
    if plan.get('handshake') != 'job_assigned':
        raise ValueError('owner_handshake_required')
    incoming = open(plan['stdin_file'], 'rb') if plan.get('stdin_file') else subprocess.DEVNULL
    try:
        process = subprocess.Popen(plan['argv'], cwd=plan['cwd'], stdin=incoming, shell=False)
        save(Path(plan['record_dir'])/'business-process.json', observe(process.pid))
        return process.wait()
    finally:
        if incoming != subprocess.DEVNULL:
            incoming.close()


if __name__ == '__main__':
    sys.exit(main())
