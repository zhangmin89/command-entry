"""Record read_text boundary behavior without changing either implementation."""
import json
import os
from pathlib import Path
import sys
import uuid


def main():
    if len(sys.argv) != 1:
        raise ValueError('This script accepts no arguments.')
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))
    from server import Server
    from tests.test_csharp_migration import Client
    executable = Path(os.environ.get('COMMAND_ENTRY_TEST_EXE', str(root / 'artifacts/command-entry-win-x64/CommandEntry.exe'))).resolve()
    if not executable.is_file():
        raise FileNotFoundError(f'Build the C# executable first or set COMMAND_ENTRY_TEST_EXE: {executable}')
    directory = root / '.codex-command-records' / ('read-text-parity-' + str(uuid.uuid4()))
    directory.mkdir(parents=True)
    policy = json.loads((root / 'policy.json').read_text(encoding='utf-8'))
    policy.update(working_roots=[str(directory)], read_roots=None,
                  serve_root=str(directory / 'serve-input'), log_root=str(directory / 'logs'))
    policy_file = directory / 'policy.json'
    policy_file.write_text(json.dumps(policy), encoding='utf-8')
    client = Client(policy_file, executable=executable)
    try:
        reference = Server(policy_file)
        observations = []
        for name, data in (
            ('cr_bad', b'good\r\xff'), ('lf_bad', b'good\n\xff'),
            ('crlf_bad', b'good\r\n\xff'), ('inside_bad', b'go\xffod\n'),
            ('cr_valid', b'good\rnext'), ('cr_eof', b'good\r'),
            ('next_chunk_bad', b'good\n' + b'x' * 65531 + b'\xff'),
            ('chunk_split_utf8', b'good\n' + b'x' * 65530 + '中'.encode()),
        ):
            path = directory / (name + '.txt')
            path.write_bytes(data)
            for count in (1, 2):
                form = {'file': str(path), 'encoding': 'utf-8', 'start_line': 1, 'max_lines': count}
                observations.append({'case': name, 'count': count,
                    'python': reference.tool_read_text(form),
                    'csharp': client.call('read_text', **form)})
        report = directory / 'read-text-parity.json'
        report.write_text(json.dumps(observations, ensure_ascii=True, indent=2), encoding='utf-8')
        if len(json.loads(report.read_text(encoding='utf-8'))) != 16:
            raise AssertionError('The diagnostic report is incomplete.')
        print(json.dumps({'report': str(report), 'cases': [
            {'case': item['case'], 'count': item['count'], **{
                engine: {key: item[engine][key] for key in
                    ('error', 'lines_served', 'total_lines_known', 'remaining', 'decode_warning')
                    if key in item[engine]} for engine in ('python', 'csharp')}}
            for item in observations]}, ensure_ascii=True))
    finally:
        client.close()


if __name__ == '__main__':
    main()
