"""Versioned request shapes. Preparation never resolves or opens business paths."""
import hashlib
import json
import ntpath
import os
from pathlib import Path
import time
import uuid

VERSION = '2.0.0-candidate.3-closeout.2'
NAMESPACE = uuid.UUID('a93e3e64-c90b-4ca6-a8da-bcf070c04196')
OPERATIONS = {'location', 'read_text', 'native', 'script', 'python_unittest', 'status', 'output', 'cancel'}


class Invalid(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise Invalid(reason)


def packed(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode('utf-8')


def digest(value):
    return hashlib.sha256(packed(value)).hexdigest()


def request_digest(req):
    return digest({key:value for key,value in req.items() if key != 'version'})


def matches_request(fingerprint, req):
    if fingerprint == request_digest(req):
        return True
    # These two observed candidate formats included the build label in identity.
    return any(fingerprint == digest(dict(req, version=label)) for label in
               ('2.0.0-candidate.1', '2.0.0-candidate.2'))


def publish_new(path, value):
    """Windows rename publishes a complete file and never replaces an existing one."""
    path = Path(path)
    temp = path.with_name(path.name + '.' + str(uuid.uuid4()) + '.pending')
    write_new(temp, value)
    try:
        os.rename(temp, path)
    finally:
        # Only our unpublished scratch file is removed; records are never removed.
        if temp.exists():
            temp.unlink()


def absolute(value):
    require(isinstance(value, str) and value and '\0' not in value, 'invalid_path')
    require(ntpath.isabs(value) and bool(ntpath.splitdrive(value)[0]), 'absolute_windows_path_required')
    return ntpath.normpath(value)


def shape(source):
    require(isinstance(source, dict), 'request_object_required')
    req = json.loads(json.dumps(source))
    known = {'task_ref','step_ref','attempt','previous_request','operation','cwd','program','language','script','args','parameters_file','stdin_file','input_paths','required_tools','encoding','file','start_line','line_count','execution_id','stream','offset','count','artifacts','acceptance','expected_versions','wait_receipt'}
    require(not set(req).difference(known), 'unknown_request_fields')
    for field in ('task_ref','step_ref'):
        require(isinstance(req.get(field), str) and 0 < len(req[field]) <= 160, field + '_required')
    require(req.get('operation') in OPERATIONS, 'unsupported_operation')
    req['cwd'] = absolute(req['cwd'])
    req.setdefault('attempt', 0)
    require(type(req['attempt']) is int and req['attempt'] >= 0, 'invalid_attempt')
    if req['attempt']:
        require(str(uuid.UUID(req.get('previous_request', ''))) == req['previous_request'], 'previous_request_required')
    else:
        require('previous_request' not in req, 'initial_attempt_has_no_previous_request')
    require(isinstance(req.get('args', []), list) and all(isinstance(a, str) and '\0' not in a for a in req.get('args', [])), 'args_must_be_strings')
    if 'stdin_file' in req:
        require(req['operation'] in ('native','script','python_unittest'), 'stdin_file_requires_execution_operation')
    for field in ('script','parameters_file','file','stdin_file'):
        if field in req:
            req[field] = absolute(req[field])
    for field in ('input_paths','required_tools'):
        require(isinstance(req.get(field, []), list), field + '_must_be_array')
        if field in req:
            req[field] = [absolute(x) for x in req[field]]
    require(req.get('encoding', 'utf-8') in ('utf-8','gbk','utf-16-le'), 'unsupported_encoding')
    if req['operation'] in ('native','script','python_unittest'):
        require(isinstance(req.get('program'), str), 'program_identifier_required')
    if req['operation'] == 'script':
        require(req.get('language') in ('python','powershell','javascript','bash') and 'script' in req, 'script_language_and_reference_required')
    if req['operation'] == 'read_text':
        require('file' in req, 'file_required')
        require(type(req.get('start_line', 1)) is int and req.get('start_line', 1) >= 1, 'invalid_start_line')
        require(type(req.get('line_count', 100)) is int and 1 <= req.get('line_count', 100) <= 1000, 'line_count_range_1_1000')
    if req['operation'] in ('status','output','cancel'):
        require(str(uuid.UUID(req.get('execution_id', ''))) == req['execution_id'], 'execution_id_required')
    if 'wait_receipt' in req:
        require(req['operation'] == 'status', 'wait_receipt_only_for_status')
        require(req['wait_receipt'] == 'host-'+req['execution_id']+'.json', 'wait_receipt_must_match_execution')
    if req['operation'] == 'output':
        require(req.get('stream', 'stdout') in ('stdout','stderr'), 'invalid_stream')
        require(type(req.get('offset', 0)) is int and req.get('offset', 0) >= 0, 'invalid_offset')
        require(type(req.get('count', 2048)) is int and 1 <= req.get('count', 2048) <= 4096, 'output_count_range_1_4096')
    artifacts = req.get('artifacts', {})
    require(isinstance(artifacts, dict), 'artifacts_object_required')
    for name, path in artifacts.items():
        require(isinstance(name, str) and name, 'artifact_name_required')
        artifacts[name] = absolute(path)
    conditions = req.get('acceptance', [])
    require(isinstance(conditions, list), 'acceptance_array_required')
    for condition in conditions:
        require(isinstance(condition, dict) and condition.get('artifact') in artifacts, 'acceptance_must_reference_declared_artifact')
        require(condition.get('kind') in ('exists','json_equals','sha256'), 'unsupported_acceptance')
        if condition['kind'] != 'exists':
            require('expected' in condition, 'expected_acceptance_value_required')
    versions = req.get('expected_versions', {})
    require(isinstance(versions, dict), 'expected_versions_object_required')
    req['expected_versions'] = {absolute(p):h for p,h in versions.items()}
    require(all(isinstance(h, str) and len(h) == 64 and set(h) <= set('0123456789abcdef') for h in versions.values()), 'invalid_content_digest')
    req['request_id'] = str(uuid.uuid5(NAMESPACE, packed([req['task_ref'], req['step_ref'], req['attempt']]).decode()))
    req['logical_id'] = str(uuid.uuid5(NAMESPACE, packed([req['task_ref'], req['step_ref']]).decode()))
    req['version'] = VERSION
    return req


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def write_new(path, value):
    with Path(path).open('xb') as target:
        target.write(packed(value))
        target.flush()
        os.fsync(target.fileno())


def save(path, value):
    path = Path(path)
    temp = path.with_name(path.name + '.' + str(uuid.uuid4()) + '.tmp')
    write_new(temp, value)
    # Concurrent readers open the target without FILE_SHARE_DELETE, so the
    # atomic replace can hit a transient sharing violation. Retry briefly;
    # a persistent failure still propagates as an honest write error.
    for attempt in range(5):
        try:
            os.replace(temp, path)
            return
        except PermissionError:
            if attempt == 4:
                raise
            time.sleep(0.02)


def load_policy(path):
    policy = read_json(path)
    require(policy.get('version') == 2, 'policy_version_required')
    return policy
