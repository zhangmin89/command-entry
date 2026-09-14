"""Observation-week metrics from envelope-only sources (plan stage 5).

Sources: sentinel hook-records (deny rate), server-events.jsonl (restarts,
dedup hits, rejections) and the serve-input root (execution count). Nothing
here reads business output or command content. Usage:

    python scripts/collect_metrics.py --records <dir> --events <file> --serve <dir>
"""
import argparse
import json
from pathlib import Path


def load_jsonl(path):
    if not Path(path).is_file():
        return []
    events = []
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        try:
            events.append(json.loads(line))
        except ValueError:
            continue
    return events


def collect(records_dir, events_file, serve_dir):
    hook = [json.loads(p.read_text(encoding='utf-8'))
            for p in sorted(Path(records_dir).glob('*.json'))] if Path(records_dir).is_dir() else []
    events = load_jsonl(events_file)
    serve = [p for p in Path(serve_dir).glob('*/request.json')] if Path(serve_dir).is_dir() else []
    shell_denied = sum(1 for item in hook if item.get('route') == 'shell_denied')
    invalid_denied = sum(1 for item in hook if item.get('route') == 'invalid_event_denied')
    total_hook = len(hook)
    starts = [e for e in events if e.get('kind') == 'start_operation']
    return {
        'hook': {
            'total_decisions': total_hook,
            'shell_denied': shell_denied,
            'invalid_event_denied': invalid_denied,
            'passthrough': total_hook - shell_denied - invalid_denied,
            'deny_rate': round((shell_denied + invalid_denied) / total_hook, 4) if total_hook else None,
        },
        'server': {
            # R10: startup events include the first start and multi-instance
            # starts; they are NOT proven restarts. Keep the raw count honest.
            'startup_events': sum(1 for e in events if e.get('kind') == 'startup'),
            'start_calls': len(starts),
            'in_flight_dedup_hits': sum(1 for e in starts if e.get('dedup')),
            'retries': sum(1 for e in starts if e.get('retry')),
            'rejections_by_reason': {
                reason: sum(1 for e in events if e.get('kind') == 'rejected' and e.get('reason') == reason)
                for reason in sorted({e.get('reason') for e in events if e.get('kind') == 'rejected'}
                                    - {None})},
            'whitelist_misses': sum(1 for e in events
                                    if e.get('kind') == 'rejected' and 'program_not_configured' in str(e.get('reason', ''))),
        },
        'executions': {'serve_inputs': len(serve)},
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--records', required=True)
    parser.add_argument('--events', required=True)
    parser.add_argument('--serve', required=True)
    options = parser.parse_args()
    print(json.dumps(collect(options.records, options.events, options.serve),
                     ensure_ascii=True, indent=2))
