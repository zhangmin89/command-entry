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
from windows_state import (FileMutex, observe, spawn_creation_flags,
                           terminate_if_same_instance)

VERSION = 'pure-beta.server.2'
TERMINAL = {'exited', 'rejected', 'timed_out', 'cancelled', 'unknown', 'tool_error'}
# Only these prove the business ended. unknown/tool_error mean "not confirmed";
# they must never justify starting a duplicate (review R3).
CONFIRMED_TERMINAL = {'exited', 'rejected', 'timed_out', 'cancelled'}
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
        # R2: normalize before hashing so semantically identical forms share
        # one identity (omitted args == [], raw workdir == resolved path,
        # explicit null == field absent). Plain argument strings keep meaning.
        content = {key: value for key, value in form.items()
                   if key != 'previous_execution' and value is not None}
        content['args'] = content.get('args') or []
        content['workdir'] = str(cwd)
        content_fingerprint = digest(content)

        # R1: atomic cross-instance claim before any identity is assigned.
        outcome, claimed_id, claim_dir = self.claim_execution(content_fingerprint)
        if outcome == 'pending':
            raise Invalid('claim_pending_unconfirmed_retry_later')
        if outcome == 'existing':
            existing_record = self.context(Path(read_json(
                self.serve_root / claimed_id / 'request.json')['business']['cwd']).resolve()) / claimed_id
            existing_state = self.snapshot(existing_record) if existing_record.is_dir() \
                else {'state': 'unknown', 'reason': 'record_missing'}
            state_name = existing_state['state']
            if state_name not in CONFIRMED_TERMINAL and not self.abandoned_confirmed(existing_record):
                blocked = state_name in ('unknown', 'tool_error')
                return {'execution_id': claimed_id, 'state': state_name,
                        'in_flight_dedup': not blocked, 'dedup_blocked': blocked,
                        'orphan_guaranteed': self.orphan_guaranteed,
                        'record_dir': str(existing_record),
                        'note': 'Instance state is unconfirmed; a duplicate is NOT started. '
                                'Use cancel to confirm abandonment before a new intent.'
                        if blocked else 'Same content still running; returning the existing id.'}
            # Confirmed terminal or confirmed abandoned: a new intent proceeds
            # and the claim is re-published with the new execution id below.

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
        try:
            require(not self.policy.get('require_orphan_guarantee') or self.orphan_guaranteed,
                    'orphan_guarantee_required_but_unavailable')
            directory = self.serve_root / execution_id
            try:
                directory.mkdir(parents=True, exist_ok=False)
            except FileExistsError:
                # A record with this identity already exists (legacy or a
                # same-seq winner). Re-point the claim and classify it.
                rival = self.find_execution_by_fingerprint(content_fingerprint)
                require(rival is not None, 'serve_dir_collision_without_match')
                save(claim_dir / 'claim.json', {'execution_id': rival,
                                                'republished_at_unix': time.time()})
                return self.classify_existing(rival)
            envelope = {'schema_version': 2, 'business': business,
                        'fingerprint': request_digest(req),
                        'content_fingerprint': content_fingerprint}
            write_new(directory / 'request.json', envelope)
            write_new(directory / 'policy.json', json.loads(self.policy_path.read_text(encoding='utf-8-sig')))
            # Publish the identity into the claim BEFORE spawning: after this
            # point any instance can learn the execution id from the claim.
            save(claim_dir / 'claim.json', {'execution_id': execution_id,
                                            'published_at_unix': time.time()})
        except Exception:
            # Our own failure before publishing must not block others for the
            # full claim timeout; rmdir only succeeds while still empty.
            if outcome == 'claim':
                try:
                    claim_dir.rmdir()
                except OSError:
                    pass
            raise

        try:
            subprocess.Popen([self.policy['python'], '-X', 'utf8',
                              str(Path(entry_v2.__file__).resolve()), 'serve', '--record-dir', str(directory)],
                             creationflags=self.flags, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             cwd=str(cwd), shell=False)
        except OSError as error:
            raise Invalid('entry_child_spawn_failed: ' + str(error)[:200])
        # Close the dedup race: the start response returns only after the
        # entry child has persisted its initial state.
        record_dir = self.context(cwd) / execution_id
        deadline = time.monotonic() + self.policy.get('start_confirm_seconds', 15)
        while not (record_dir / 'result.json').is_file() and time.monotonic() < deadline:
            time.sleep(0.1)
        if not (record_dir / 'result.json').is_file():
            # R5: the caller must be able to recover this instance through the
            # public status tool; include the id and any child-side error.
            serve_error = directory / 'serve-error.json'
            detail = read_json(serve_error) if serve_error.is_file() else None
            return {'execution_id': execution_id, 'request_id': req['request_id'],
                    'state': 'unconfirmed_start', 'in_flight_dedup': False,
                    'orphan_guaranteed': self.orphan_guaranteed,
                    'record_dir': str(record_dir),
                    'serve_error': detail,
                    'note': 'Entry child did not confirm its initial state within 15s. '
                            'Do NOT rerun blindly; query status for this execution_id first.'}
        return {'execution_id': execution_id, 'request_id': req['request_id'],
                'state': 'starting', 'in_flight_dedup': False,
                'orphan_guaranteed': self.orphan_guaranteed,
                'record_dir': str(record_dir),
                'note': 'Spawned detached entry child; query status/wait for the outcome.'}

    def classify_existing(self, execution_id):
        """Second look at an already-claimed execution (R1/R3 semantics)."""
        business = read_json(self.serve_root / execution_id / 'request.json')['business']
        record = self.context(Path(business['cwd']).resolve()) / execution_id
        state = self.snapshot(record) if record.is_dir() else {'state': 'unknown', 'reason': 'record_missing'}
        state_name = state['state']
        blocked = state_name not in CONFIRMED_TERMINAL and not self.abandoned_confirmed(record)
        return {'execution_id': execution_id, 'state': state_name,
                'in_flight_dedup': not blocked, 'dedup_blocked': blocked,
                'orphan_guaranteed': self.orphan_guaranteed, 'record_dir': str(record)}

    def find_execution_by_fingerprint(self, content_fingerprint):
        """Newest serve record carrying this content fingerprint, if any."""
        best = None
        for path in self.serve_root.glob('*/request.json'):
            try:
                if read_json(path).get('content_fingerprint') != content_fingerprint:
                    continue
            except (ValueError, OSError):
                continue
            if best is None or path.stat().st_mtime > best.stat().st_mtime:
                best = path
        return best.parent.name if best else None

    def claim_execution(self, content_fingerprint):
        """Atomic cross-instance claim (review R1).

        Returns (outcome, execution_id_or_None, claim_dir):
        ('claim', None, dir)     — this caller owns a fresh claim;
        ('existing', id, dir)    — an identity is published (or healable);
        ('pending', None, dir)   — an unfinished claim too fresh to declare
                                   abandoned; the caller must NOT start.
        """
        claims_root = self.serve_root / '_claims'
        claims_root.mkdir(parents=True, exist_ok=True)
        claim_dir = claims_root / content_fingerprint
        try:
            claim_dir.mkdir()
            return ('claim', None, claim_dir)
        except FileExistsError:
            pass
        claim_file = claim_dir / 'claim.json'
        if claim_file.is_file():
            return ('existing', read_json(claim_file)['execution_id'], claim_dir)
        healed = self.find_execution_by_fingerprint(content_fingerprint)
        if healed:
            save(claim_file, {'execution_id': healed, 'healed_at_unix': time.time()})
            return ('existing', healed, claim_dir)
        timeout = self.policy.get('claim_timeout_seconds', 120)
        if time.time() - claim_dir.stat().st_mtime < timeout:
            return ('pending', None, claim_dir)
        try:
            claim_dir.rmdir()  # succeeds only while still empty (unpublished)
        except OSError:
            return ('pending', None, claim_dir)  # a claim.json appeared meanwhile
        return self.claim_execution(content_fingerprint)

    def abandoned_confirmed(self, record):
        """R3(b): a cancel-outcome sidecar proving every known process is dead."""
        outcome = record / 'cancel-outcome.json'
        if not outcome.is_file():
            return False
        try:
            return read_json(outcome).get('all_known_processes_confirmed_dead') is True
        except (ValueError, OSError):
            return False

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
        require(old['state'] in CONFIRMED_TERMINAL, 'previous_attempt_not_confirmed_terminal')
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
        if state['state'] in CONFIRMED_TERMINAL:
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
            current_state = self.snapshot(directory)['state']
            if current_state in CONFIRMED_TERMINAL:
                return {'execution_id': directory.name, 'state': current_state,
                        'cancel_action': action + '_and_finished_within_grace'}
            time.sleep(1)
        # R3(b): hard path — TerminateProcess returning success does NOT prove
        # exit. Terminate each known instance by pid+creation_time, then poll
        # until death is observed. The record itself is never rewritten; the
        # verdict goes into a separate cancel-outcome.json sidecar, and only
        # "all known processes confirmed dead" allows a future new intent.
        state = self.snapshot(directory)
        owner = state.get('owner') or {}
        detail = {'owner': self.terminate_and_confirm(owner.get('pid'), owner.get('creation_time'))}
        birth_file = directory / 'business-process.json'
        if birth_file.is_file():
            birth = read_json(birth_file)
            detail['business'] = self.terminate_and_confirm(birth.get('pid'), birth.get('creation_time'))
        all_dead = detail['owner'].get('confirmed_dead') is True and \
            all(item.get('confirmed_dead') is True for key, item in detail.items() if key != 'owner')
        outcome = {'checked_at_unix': time.time(),
                   'all_known_processes_confirmed_dead': all_dead, **detail}
        save(directory / 'cancel-outcome.json', outcome)
        return {'execution_id': directory.name,
                'state': self.snapshot(directory)['state'],
                'cancel_action': 'hard_kill_after_grace',
                'confirmed_dead': all_dead, 'detail': detail,
                'note': 'Record is not rewritten; unknown stays unknown. A new intent is '
                        'allowed only when all known processes are confirmed dead.'}

    def terminate_and_confirm(self, pid, creation_time):
        """Terminate one exact instance and verify death by observation (R3)."""
        if not isinstance(pid, int) or creation_time is None:
            return {'terminated': False, 'confirmed_dead': False, 'reason': 'instance_identity_missing'}
        report = terminate_if_same_instance(pid, creation_time)
        deadline = time.monotonic() + self.policy.get('cancel_confirm_seconds', 10)
        while time.monotonic() < deadline:
            current = observe(pid)
            # Our instance is dead when the pid is gone or has been reused by
            # a different creation time. alive=None stays unconfirmed.
            if current.get('alive') is False or \
                    (current.get('creation_time') is not None and current['creation_time'] != creation_time):
                report['confirmed_dead'] = True
                return report
            time.sleep(0.2)
        report['confirmed_dead'] = False
        return report

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
            observed = None
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
                    # R9: report THIS round's observation, computed before the
                    # journal update — never compare current against itself.
                    return {'execution_id': directory.name, 'state': state['state'],
                            'wait_outcome': 'budget_exhausted',
                            'suggest_poll_seconds': interval,
                            'observation': observed}
                time.sleep(min(interval, remaining))

    # ---------- read_text (plan 0.4, A1; R6/R7 streaming) ----------

    LINE_ENDINGS = ('\n', '\r', '\x0b', '\x0c', '\x1c', '\x1d', '\x1e',
                    '\x85', '\u2028', '\u2029')

    def tool_read_text(self, form):
        require(isinstance(form, dict), 'form_object_required')
        known = {'file', 'start_line', 'max_lines', 'encoding'}
        require(not set(form).difference(known), 'unknown_form_fields')
        target = form.get('file')
        require(isinstance(target, str) and target, 'file_required')
        path = Path(target).resolve(strict=True)
        # R8: an explicit [] means deny-all; only a missing/null key inherits
        # working_roots. Never silently widen an explicit restriction.
        configured_roots = self.policy.get('read_roots')
        roots = self.policy['working_roots'] if configured_roots is None else configured_roots
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
        quota = self.policy.get('read_quota_bytes', 65536)
        total_bytes = path.stat().st_size  # O(1); never derived from a scan
        with path.open('rb') as source:
            prefix = source.read(4096)
            source.seek(0)
            if encoding is None:
                encoding = sniff_bom(prefix) or 'utf-8'
            # R7: chunked binary reading with a carry buffer for characters
            # split across chunk edges. A strict fault decodes only the sound
            # prefix of the current chunk: a decode error BEYOND the requested
            # range never fails an already-servable prefix.
            carry = b''
            pending = ''
            line_index = 0
            payload_parts = []
            served_lines = 0
            served_bytes = 0
            eof = False
            stopped_early = False
            decode_failed = None
            while True:
                chunk = source.read(65536)
                if not chunk:
                    eof = True
                data = carry + chunk
                if not data:
                    text = ''
                else:
                    try:
                        text = data.decode(encoding, errors='strict')
                        carry = b''
                    except UnicodeDecodeError as error:
                        if not eof and error.reason == 'unexpected end of data':
                            text = data[:error.start].decode(encoding)
                            carry = data[error.start:]
                        else:
                            text = data[:error.start].decode(encoding) if error.start else ''
                            carry = b''
                            decode_failed = error
                pending += text
                parts = pending.splitlines(keepends=True)
                if parts and not eof:
                    tail = parts[-1]
                    if tail.endswith('\r') or not tail.endswith(self.LINE_ENDINGS):
                        pending = parts.pop()  # incomplete or split \r\n
                    else:
                        pending = ''
                elif eof:
                    pending = ''
                for line in parts:
                    line_index += 1
                    if line_index < start:
                        continue
                    if served_lines >= count:
                        stopped_early = True
                        break
                    line_bytes = len(line.encode('utf-8'))
                    if line_bytes > quota:
                        return {'error': 'single_line_exceeds_quota', 'line_number': line_index,
                                'line_bytes': line_bytes, 'quota_bytes': quota,
                                'note': 'A single line over quota cannot be served whole; '
                                        'truncation is forbidden.'}
                    if served_bytes + line_bytes > quota:
                        stopped_early = True
                        break
                    payload_parts.append(line)
                    served_lines += 1
                    served_bytes += line_bytes
                if served_lines >= count and not eof:
                    # The requested range is complete even when no further
                    # line exists to trigger the in-loop stop check. At EOF
                    # this is a genuinely complete scan instead.
                    stopped_early = True
                if stopped_early or eof or decode_failed is not None:
                    break
        if decode_failed is not None and not stopped_early:
            suggestions = [name for name in ('gbk', 'utf-16-le', 'utf-16', 'utf-8')
                           if strict_decodable(prefix, name)]
            return {'error': 'decoding_failed_strict', 'encoding_tried': encoding,
                    'detail': str(decode_failed)[:200],
                    'suggested_encodings': suggestions,
                    'note': 'Pass an explicit encoding parameter; silent U+FFFD is forbidden. '
                            'Suggestions are evaluated on the first 4096 bytes only.'}
        complete_scan = eof and not stopped_early and decode_failed is None
        result = {'file': str(path), 'encoding_used': encoding,
                  'text': ''.join(payload_parts), 'start_line': start,
                  # R6: counted from lines actually served, not newline chars.
                  'lines_served': served_lines,
                  # R7: unknown unless the scan reached end of file; never estimated.
                  'total_lines': line_index if complete_scan else None,
                  'total_lines_known': complete_scan,
                  'total_bytes': total_bytes,
                  'remaining': stopped_early,
                  'next_start_line': start + served_lines,
                  'decoding_loss': False}
        if decode_failed is not None:
            result['decode_warning'] = ('The requested range was fully served; a strict '
                                        'decode fault exists beyond it: ' + str(decode_failed)[:150])
        return result

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
            # R10: log a fixed, classifiable reason code. Invalid messages are
            # controlled codes (strip any appended dynamic detail); other
            # exception messages may contain paths and stay as type names.
            code = str(error).split(':', 1)[0][:80] if isinstance(error, Invalid) \
                else type(error).__name__
            self.log_event('rejected', tool=name, error_kind=type(error).__name__, reason=code)
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
     'description': 'Stateless streaming range read (A1): file, start_line (1-based), max_lines (1..1000), optional encoding. Returns the exact requested range with coverage metadata; continue with next_start_line; strict decoding, no silent U+FFFD, explicit error for oversized single lines. total_lines is null unless the scan reached end of file (see total_lines_known).',
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
