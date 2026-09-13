"""Pure-beta exec server: stateless stdio MCP around the V2 execution entry.

Responsibilities only: schema forms, policy validation and envelope building
(inheriting prepare's job), spawning detached entry children, and read-only
queries over record directories. The server holds no execution state; an
entry child owns its Windows Job and runs the full V2 lifecycle, so a server
crash never kills in-flight business work.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import uuid

from common import (Invalid, digest, load_policy, packed, publish_new, read_json,
                    request_digest, require, save, shape, write_new)
import adapter
import entry_v2
import wait_state
from windows_state import FileMutex, spawn_creation_flags, terminate_if_same_instance

VERSION = 'pure-beta.server.1'
TERMINAL = {'exited', 'rejected', 'timed_out', 'cancelled', 'unknown', 'tool_error'}
IDENTITY_FREE = ('task_ref', 'step_ref', 'attempt', 'previous_request')
START_FIELDS = {'operation', 'program', 'language', 'script', 'parameters_file', 'args',
                'stdin_file', 'input_paths', 'required_tools', 'encoding',
                'artifacts', 'acceptance', 'expected_versions', 'workdir', 'previous_execution'}
LOCATION_FIELDS = {'execution_id', 'cwd'}


def execution_identity(request_id):
    return str(uuid.uuid5(uuid.UUID(request_id), 'execution-instance'))


def sniff_bom(raw):
    if raw.startswith(b'\xef\xbb\xbf'):
        return 'utf-8-sig'
    if raw.startswith(b'\xff\xfe') or raw.startswith(b'\xfe\xff'):
        return 'utf-16'
    return None


def strict_decodable(raw, encoding):
    try:
        raw.decode(encoding)
        return True
    except (UnicodeDecodeError, LookupError):
        return False


class Server:
    def __init__(self, policy_path, binding_path=None):
        self.policy_path = Path(policy_path).resolve()
        self.policy = load_policy(self.policy_path)
        if binding_path:
            self.verify_binding(binding_path)
        self.serve_root = Path(self.policy['serve_root']).resolve()
        self.serve_root.mkdir(parents=True, exist_ok=True)
        self.log_root = Path(self.policy.get('log_root') or (self.policy_path.parent / 'logs')).resolve()
        # Plan 0.1: probe once at startup and log it. Breakaway decides whether
        # entry children can outlive this server.
        self.flags, self.orphan_guaranteed = spawn_creation_flags()
        self.log_event('startup', flags=hex(self.flags), orphan_guaranteed=self.orphan_guaranteed)

    def verify_binding(self, binding_path):
        """Stage 5 self-check: this file set + policy must match the anchor."""
        binding = read_json(binding_path)
        require(binding.get('schema_version') == 2, 'binding_version_required')
        require(str(Path(binding['policy']['path']).resolve()).lower() == str(self.policy_path).lower(),
                'binding_policy_path_mismatch')
        require(hashlib.sha256(self.policy_path.read_bytes()).hexdigest() == binding['policy']['sha256'],
                'policy_changed_since_review')
        for item in binding['runtime_files']:
            require(hashlib.sha256(Path(item['path']).read_bytes()).hexdigest() == item['sha256'],
                    'runtime_changed_since_review_' + Path(item['path']).name)

    def log_event(self, kind, **fields):
        """Envelope-only diagnostics; never parameters, results or paths of calls."""
        try:
            self.log_root.mkdir(parents=True, exist_ok=True)
            with (self.log_root / 'server-events.jsonl').open('a', encoding='utf-8') as stream:
                stream.write(json.dumps(dict(kind=kind, ts=time.time(), **fields),
                                        ensure_ascii=True) + '\n')
        except OSError:
            pass  # Diagnostics must never break serving.

    # ---------- shared helpers ----------

    def context(self, cwd):
        return entry_v2.context(self.policy, cwd)

    def locate(self, execution_id):
        require(str(uuid.UUID(execution_id)) == execution_id, 'execution_id_required')
        entry = self.serve_root / execution_id / 'request.json'
        require(entry.is_file(), 'execution_not_found')
        business = read_json(entry)['business']
        directory = self.context(Path(business['cwd']).resolve()) / execution_id
        return directory, business['cwd']

    def snapshot(self, directory):
        return entry_v2.snapshot(directory)

    # ---------- start_operation ----------

    def tool_start(self, form):
        require(isinstance(form, dict), 'form_object_required')
        require(not set(form).difference(START_FIELDS), 'unknown_form_fields')
        operation = form.get('operation')
        require(operation in ('native', 'script', 'python_unittest'), 'unsupported_operation')
        workdir = form.get('workdir')
        require(isinstance(workdir, str) and workdir, 'workdir_required')
        cwd = Path(workdir).resolve(strict=True)
        require(cwd.is_dir(), 'working_directory_missing')
        require(any(cwd == Path(root).resolve() or cwd.is_relative_to(Path(root).resolve())
                    for root in self.policy['working_roots']), 'storage_context_not_configured_for_cwd')
        program = form.get('program')
        require(isinstance(program, str) and program in self.policy.get('programs', {}),
                'program_not_configured')
        if not isinstance(form.get('args', []), list):
            raise Invalid('args_must_be_array')
        content = {key: value for key, value in form.items() if key != 'previous_execution'}
        content_fingerprint = digest(content)

        # In-flight dedup (plan 0.3): same content still RUNNING returns the id.
        for existing in self.running_same_content(content_fingerprint):
            business = read_json(self.serve_root / existing / 'request.json')['business']
            return {'execution_id': existing, 'state': 'starting',
                    'in_flight_dedup': True, 'orphan_guaranteed': self.orphan_guaranteed,
                    'record_dir': str(self.context(Path(business['cwd']).resolve()) / existing)}

        if 'previous_execution' in form:
            task_ref, step_ref, previous_request, origin_attempt = self.resolve_previous(
                form['previous_execution'], content_fingerprint)
            attempt = origin_attempt + 1
        else:
            seq = 1 + sum(1 for path in self.serve_root.glob('*/request.json')
                          if read_json(path).get('content_fingerprint') == content_fingerprint)
            task_ref, step_ref, previous_request = 'mcp-direct', content_fingerprint[:12] + '-' + str(seq), None
            attempt = 0
        business = {key: value for key, value in form.items()
                    if key not in ('workdir', 'previous_execution')}
        business.update({'task_ref': task_ref, 'step_ref': step_ref, 'attempt': attempt,
                         'cwd': workdir, 'operation': operation})
        if previous_request:
            business['previous_request'] = previous_request
        req = shape(business)
        execution_id = execution_identity(req['request_id'])

        # Fail closed before creating anything on disk (plan 0.1).
        require(not self.policy.get('require_orphan_guarantee') or self.orphan_guaranteed,
                'orphan_guarantee_required_but_unavailable')
        directory = self.serve_root / execution_id
        directory.mkdir(parents=True, exist_ok=False)
        envelope = {'schema_version': 2, 'business': business,
                    'fingerprint': request_digest(req),
                    'content_fingerprint': content_fingerprint}
        write_new(directory / 'request.json', envelope)
        write_new(directory / 'policy.json', json.loads(self.policy_path.read_text(encoding='utf-8-sig')))

        subprocess.Popen([self.policy['python'], '-X', 'utf8',
                          str(Path(entry_v2.__file__).resolve()), 'serve', '--record-dir', str(directory)],
                         creationflags=self.flags, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         cwd=str(cwd), shell=False)
        # Close the dedup race: the start response returns only after the
        # entry child has persisted its initial state.
        record_dir = self.context(cwd) / execution_id
        deadline = time.monotonic() + 15
        while not (record_dir / 'result.json').is_file() and time.monotonic() < deadline:
            time.sleep(0.1)
        require((record_dir / 'result.json').is_file(), 'entry_child_did_not_start')
        return {'execution_id': execution_id, 'request_id': req['request_id'],
                'state': 'starting', 'in_flight_dedup': False,
                'orphan_guaranteed': self.orphan_guaranteed,
                'record_dir': str(record_dir),
                'note': 'Spawned detached entry child; query status/wait for the outcome.'}

    def running_same_content(self, content_fingerprint):
        for path in self.serve_root.glob('*/request.json'):
            envelope = read_json(path)
            if envelope.get('content_fingerprint') != content_fingerprint:
                continue
            business = envelope['business']
            directory = self.context(Path(business['cwd']).resolve()) / path.parent.name
            if directory.is_dir() and self.snapshot(directory)['state'] not in TERMINAL:
                yield path.parent.name

    def resolve_previous(self, execution_id, content_fingerprint):
        require(str(uuid.UUID(execution_id)) == execution_id, 'execution_id_required')
        entry = self.serve_root / execution_id / 'request.json'
        require(entry.is_file(), 'previous_execution_not_found')
        envelope = read_json(entry)
        origin = shape(envelope['business'])
        require(envelope.get('content_fingerprint') == content_fingerprint,
                'previous_execution_content_mismatch')
        directory = self.context(Path(origin['cwd']).resolve()) / execution_id
        old = self.snapshot(directory)
        require(old['state'] in ('rejected', 'exited', 'timed_out', 'cancelled'),
                'previous_attempt_not_confirmed_terminal')
        return origin['task_ref'], origin['step_ref'], origin['request_id'], origin['attempt']

    # ---------- status / output / cancel ----------

    def tool_status(self, form):
        require(isinstance(form, dict), 'form_object_required')
        require(not set(form).difference(LOCATION_FIELDS), 'unknown_form_fields')
        directory, _ = self.locate(form['execution_id'])
        state = self.snapshot(directory)
        state['execution_id'] = directory.name
        return entry_v2.bounded(state)

    def tool_output(self, form):
        require(isinstance(form, dict), 'form_object_required')
        known = {'execution_id', 'cwd', 'stream', 'offset', 'count'}
        require(not set(form).difference(known), 'unknown_form_fields')
        directory, _ = self.locate(form['execution_id'])
        state = self.snapshot(directory)
        stream = form.get('stream', 'stdout')
        require(stream in ('stdout', 'stderr'), 'invalid_stream')
        output_path = directory / (stream + '.txt')
        require(output_path.is_file(), 'retained_output_unavailable')
        text = output_path.read_text(encoding='utf-8')
        offset = form.get('offset', 0)
        count = form.get('count', 2048)
        require(type(offset) is int and offset >= 0, 'invalid_offset')
        require(type(count) is int and 1 <= count <= 4096, 'output_count_range_1_4096')
        return {'execution_id': directory.name, 'state': state['state'],
                'stream': stream, 'offset_characters': offset,
                'text': text[offset:offset + count],
                'next_offset': min(offset + count, len(text)),
                'retained_view_end': offset + count >= len(text),
                'metadata': state.get('output', {}).get(stream)}

    def tool_cancel(self, form):
        require(isinstance(form, dict), 'form_object_required')
        require(not set(form).difference(LOCATION_FIELDS), 'unknown_form_fields')
        directory, _ = self.locate(form['execution_id'])
        state = self.snapshot(directory)
        if state['state'] in TERMINAL:
            return {'execution_id': directory.name, 'state': state['state'],
                    'cancel_action': 'already_terminal'}
        try:
            write_new(directory / 'cancel-request.json',
                      {'requested_at_unix': time.time(), 'requested_by': 'exec_server'})
            action = 'cancel_request_written'
        except FileExistsError:
            action = 'cancel_request_already_present'
        grace = self.policy['cancel_grace_seconds']
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            if self.snapshot(directory)['state'] in TERMINAL:
                return {'execution_id': directory.name, 'state': self.snapshot(directory)['state'],
                        'cancel_action': action + '_and_finished_within_grace'}
            time.sleep(1)
        # Hard-kill fallback: only the exact observed owner instance is killed.
        state = self.snapshot(directory)
        owner = state.get('owner') or {}
        killed = terminate_if_same_instance(owner.get('pid'), owner.get('creation_time')) \
            if owner.get('pid') else {'terminated': False, 'reason': 'owner_missing'}
        return {'execution_id': directory.name, 'state': 'unknown',
                'cancel_action': 'hard_kill_after_grace', 'hard_kill': killed,
                'note': 'Owner terminated if same instance; record stays honest (unknown).'}

    # ---------- wait (plan 0.2) ----------

    def tool_wait(self, form):
        require(isinstance(form, dict), 'form_object_required')
        require(not set(form).difference(LOCATION_FIELDS), 'unknown_form_fields')
        directory, _ = self.locate(form['execution_id'])
        budget = self.policy['wait_budget_seconds']
        interval = self.policy['wait_poll_interval_seconds']
        threshold = self.policy.get('wait_stop_after_no_progress', 12)
        deadline = time.monotonic() + budget
        with FileMutex(directory / 'wait-state.lock'):
            journal_file = directory / 'wait-state.json'
            journal = read_json(journal_file) if journal_file.is_file() else {'count': 0, 'previous': None}
            while True:
                state = self.snapshot(directory)
                if state['state'] in TERMINAL:
                    result = entry_v2.bounded(state)
                    result['wait_outcome'] = 'terminal'
                    return result
                current = wait_state.collect(directory, state)
                if journal['previous'] is not None:
                    observed = adapter.progress(journal['previous'], current)
                    journal['count'] = 0 if observed['progress_confirmed'] else journal['count'] + 1
                    journal['previous'] = current
                    save(journal_file, journal)
                    if journal['count'] >= threshold:
                        return {'execution_id': directory.name, 'state': state['state'],
                                'wait_outcome': 'stop_automatic_wait',
                                'no_progress_count': journal['count'],
                                'no_progress_threshold': threshold,
                                'observation': observed,
                                'note': 'Consecutive observations without progress reached the policy threshold (wait_stop_after_no_progress).'}
                else:
                    journal['previous'] = current
                    save(journal_file, journal)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return {'execution_id': directory.name, 'state': state['state'],
                            'wait_outcome': 'budget_exhausted',
                            'suggest_poll_seconds': interval,
                            'observation': adapter.progress(journal['previous'], current)
                            if journal['previous'] else None}
                time.sleep(min(interval, remaining))

    # ---------- read_text (plan 0.4, A1) ----------

    def tool_read_text(self, form):
        require(isinstance(form, dict), 'form_object_required')
        known = {'file', 'start_line', 'max_lines', 'encoding'}
        require(not set(form).difference(known), 'unknown_form_fields')
        target = form.get('file')
        require(isinstance(target, str) and target, 'file_required')
        path = Path(target).resolve(strict=True)
        roots = self.policy.get('read_roots') or self.policy['working_roots']
        require(any(path == Path(root).resolve() or path.is_relative_to(Path(root).resolve())
                    for root in roots), 'file_outside_read_roots')
        require(path.is_file(), 'file_not_found')
        start = form.get('start_line', 1)
        count = form.get('max_lines', 100)
        require(type(start) is int and start >= 1, 'invalid_start_line')
        require(type(count) is int and 1 <= count <= 1000, 'max_lines_range_1_1000')
        encoding = form.get('encoding')
        if encoding is not None:
            require(encoding in ('utf-8', 'utf-8-sig', 'gbk', 'utf-16', 'utf-16-le'),
                    'unsupported_encoding')
        raw = path.read_bytes()
        if encoding is None:
            encoding = sniff_bom(raw) or 'utf-8'
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError as error:
            suggestions = [name for name in ('gbk', 'utf-16-le', 'utf-16', 'utf-8')
                           if strict_decodable(raw, name)]
            return {'error': 'decoding_failed_strict', 'encoding_tried': encoding,
                    'byte_offset': error.start, 'suggested_encodings': suggestions,
                    'note': 'Pass an explicit encoding parameter; silent U+FFFD is forbidden.'}
        lines = text.splitlines(keepends=True)
        selected = lines[start - 1:start - 1 + count]
        quota = self.policy.get('read_quota_bytes', 65536)
        payload = ''
        served = 0
        for index, line in enumerate(selected, start):
            if len(line.encode('utf-8')) > quota:
                return {'error': 'single_line_exceeds_quota', 'line_number': index,
                        'line_bytes': len(line.encode('utf-8')), 'quota_bytes': quota,
                        'note': 'A single line over quota cannot be served whole; truncation is forbidden.'}
            if served + len(line.encode('utf-8')) > quota:
                break
            payload += line
            served += len(line.encode('utf-8'))
        served_lines = payload.count('\n') + (1 if payload and not payload.endswith('\n') else 0)
        next_start = start + served_lines
        return {'file': str(path), 'encoding_used': encoding,
                'text': payload, 'start_line': start, 'lines_served': served_lines,
                'total_lines': len(lines), 'total_bytes': len(raw),
                'remaining': next_start <= len(lines),
                'next_start_line': next_start,
                'decoding_loss': False}

    # ---------- stdio JSON-RPC (framework inherited from prepare_mcp) ----------

    def dispatch(self, name, args):
        try:
            if name == 'start_operation':
                result = self.tool_start(args.get('business', args))
                self.log_event('start_operation', dedup=result.get('in_flight_dedup'),
                               retry=bool(args.get('business', args).get('previous_execution')))
                return result
            for tool in ('status', 'output', 'cancel', 'wait', 'read_text'):
                if name == tool:
                    result = getattr(self, 'tool_' + tool)(args)
                    self.log_event(tool)
                    return result
            raise Invalid('unknown_tool')
        except (Invalid, OSError, ValueError, KeyError, TypeError) as error:
            self.log_event('rejected', tool=name, reason=type(error).__name__)
            raise


TOOLS = [
    {'name': 'start_operation',
     'description': 'Start one business operation via a detached entry child. Form fields: operation (native/script/python_unittest), program, workdir, args, script, language, parameters_file, stdin_file, input_paths, required_tools, artifacts, acceptance, expected_versions, encoding, previous_execution. No timeout field: budgets come from policy. Same content while RUNNING dedups to the same id; after TERMINAL the same content is a new intent.',
     'inputSchema': {'type': 'object',
                     'properties': {
                         'operation': {'type': 'string'}, 'program': {'type': 'string'},
                         'workdir': {'type': 'string'}, 'args': {'type': 'array', 'items': {'type': 'string'}},
                         'script': {'type': 'string'}, 'language': {'type': 'string'},
                         'parameters_file': {'type': 'string'}, 'stdin_file': {'type': 'string'},
                         'input_paths': {'type': 'array', 'items': {'type': 'string'}},
                         'required_tools': {'type': 'array', 'items': {'type': 'string'}},
                         'artifacts': {'type': 'object'}, 'acceptance': {'type': 'array'},
                         'expected_versions': {'type': 'object'}, 'encoding': {'type': 'string'},
                         'previous_execution': {'type': 'string'}},
                     'required': ['operation', 'program', 'workdir'], 'additionalProperties': False}},
    {'name': 'status',
     'description': 'Read the current envelope of one execution from its record directory.',
     'inputSchema': {'type': 'object', 'properties': {'execution_id': {'type': 'string'}},
                     'required': ['execution_id'], 'additionalProperties': False}},
    {'name': 'output',
     'description': 'Paged retrieval of retained redacted output text (offset/count are Unicode characters).',
     'inputSchema': {'type': 'object',
                     'properties': {'execution_id': {'type': 'string'}, 'stream': {'type': 'string'},
                                    'offset': {'type': 'number'}, 'count': {'type': 'number'}},
                     'required': ['execution_id'], 'additionalProperties': False}},
    {'name': 'cancel',
     'description': 'Layered cancel: cancel-request.json first (graceful V2 state machine), hard-kill of the exact owner instance after cancel_grace_seconds.',
     'inputSchema': {'type': 'object', 'properties': {'execution_id': {'type': 'string'}},
                     'required': ['execution_id'], 'additionalProperties': False}},
    {'name': 'wait',
     'description': 'Blocking observation loop over the record directory, bounded by policy wait_budget_seconds. Consecutive observations without progress stop automatic waiting once the policy threshold wait_stop_after_no_progress (default 12) is reached.',
     'inputSchema': {'type': 'object', 'properties': {'execution_id': {'type': 'string'}},
                     'required': ['execution_id'], 'additionalProperties': False}},
    {'name': 'read_text',
     'description': 'Stateless full range read (A1): file, start_line (1-based), max_lines (1..1000), optional encoding. Returns the exact requested range with coverage metadata; strict decoding, no silent U+FFFD, explicit error for oversized single lines.',
     'inputSchema': {'type': 'object',
                     'properties': {'file': {'type': 'string'}, 'start_line': {'type': 'number'},
                                    'max_lines': {'type': 'number'}, 'encoding': {'type': 'string'}},
                     'required': ['file'], 'additionalProperties': False}},
]


def serve(policy_path, binding_path=None):
    try:
        server = Server(policy_path, binding_path)
    except (Invalid, OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({'fatal': 'startup_self_check_failed',
                          'kind': type(error).__name__, 'reason': str(error)[:300]},
                         ensure_ascii=True), file=sys.stderr, flush=True)
        sys.exit(125)
    for line in sys.stdin:
        try:
            message = json.loads(line)
            if 'id' not in message:
                continue
            method = message.get('method')
            if method == 'initialize':
                requested = message.get('params', {}).get('protocolVersion')
                version = requested if requested in ('2024-11-05', '2025-03-26', '2025-06-18') else '2025-06-18'
                result = {'protocolVersion': version, 'capabilities': {'tools': {}},
                         'serverInfo': {'name': 'command-entry-exec-server', 'version': VERSION}}
            elif method == 'ping':
                result = {}
            elif method == 'tools/list':
                result = {'tools': TOOLS}
            elif method == 'tools/call':
                params = message['params']
                args = params.get('arguments', {})
                try:
                    value = server.dispatch(params['name'], args)
                    result = {'content': [{'type': 'text', 'text': json.dumps(value, ensure_ascii=True)}],
                              'structuredContent': value, 'isError': False}
                except (Invalid, OSError, ValueError, KeyError, TypeError) as error:
                    result = {'content': [{'type': 'text',
                                           'text': json.dumps({'error': type(error).__name__,
                                                              'reason': str(error)[:500]})}],
                              'isError': True}
            else:
                print(json.dumps({'jsonrpc': '2.0', 'id': message['id'],
                                 'error': {'code': -32601, 'message': 'Unknown method'}}), flush=True)
                continue
            print(json.dumps({'jsonrpc': '2.0', 'id': message['id'], 'result': result}), flush=True)
        except (ValueError, KeyError, TypeError):
            print(json.dumps({'jsonrpc': '2.0', 'id': None,
                              'error': {'code': -32700, 'message': 'Invalid JSON-RPC request'}}), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--policy', required=True)
    parser.add_argument('--binding')
    options = parser.parse_args()
    serve(options.policy, options.binding)
