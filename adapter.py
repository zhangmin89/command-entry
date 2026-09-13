"""Pure host adapter. No subprocess, business file access, or permission decisions."""
import json
from common import Invalid, require


def decode_host_result(response, execution_id):
    require(isinstance(response, dict), 'host_response_object_required')
    control = {'execution_id':execution_id,'host_session_id':response.get('session_id'),
               'host_exit_code':response.get('exit_code'),'host_wall_seconds':response.get('wall_time_seconds'),
               'raw_host_retained_by_host':True}
    output = response.get('output')
    if response.get('session_id') is not None and response.get('exit_code') is None:
        return dict(control, state='running', result_available=False, next_action='query_existing_execution')
    if not isinstance(output, str) or not output.strip():
        return dict(control, state='unknown', result_available=False, reason='empty_host_result', next_action='query_existing_execution')
    if output.lstrip().startswith('Warning: truncated output'):
        return dict(control, state='unknown', result_available=False, reason='host_output_truncated', next_action='query_existing_execution')
    try:
        parsed = json.loads(output)
        if parsed.get('version') == '1.0.0':
            stream = parsed.get('stdout', {})
            control['v1_wrapper_process'] = parsed.get('process')
            if stream.get('truncated') or not stream.get('text'):
                return dict(control, state='unknown', result_available=False, reason='wrapper_result_unavailable', next_action='query_existing_execution')
            parsed = json.loads(stream['text'])
        if not isinstance(parsed, dict) or 'state' not in parsed:
            raise ValueError('invalid control shape')
        return dict(control, state=parsed['state'], result_available=True, result=parsed)
    except (ValueError,TypeError,AttributeError):
        return dict(control, state='unknown', result_available=False, reason='unreadable_control_envelope', next_action='query_existing_execution')


def progress(before, after):
    changes, unknown = [], []
    fields = [('business_observation','alive'),('business_observation','cpu_seconds'),('process','exit_code')]
    for parent, name in fields:
        old, new = before.get(parent,{}).get(name), after.get(parent,{}).get(name)
        if parent == 'process' and name in before.get(parent,{}) and old is None and new is not None:
            changes.append(parent+'.'+name)
        elif old is None or new is None:
            unknown.append(parent+'.'+name)
        elif (new > old if name == 'cpu_seconds' else old != new):
            changes.append(parent+'.'+name)
    for stream in ('stdout','stderr'):
        old = before.get('output',{}).get(stream,{}).get('captured_bytes')
        new = after.get('output',{}).get(stream,{}).get('captured_bytes')
        if old is None or new is None:
            unknown.append(stream+'_bytes')
        elif new > old:
            changes.append(stream+'_bytes')
    if 'artifact_observations' not in before or 'artifact_observations' not in after:
        unknown.append('artifact_observations')
    else:
        for name in set(before['artifact_observations']) | set(after['artifact_observations']):
            old = before['artifact_observations'].get(name)
            new = after['artifact_observations'].get(name)
            if not isinstance(old,dict) or not isinstance(new,dict) or old.get('unknown') or new.get('unknown'):
                unknown.append('artifact_observations.'+name)
            elif old != new:
                changes.append('artifact_observations.'+name)
    return {'progress_confirmed':bool(changes),'changed':changes,'unknown_metrics':unknown,
            'process_alive':after.get('business_observation',{}).get('alive')}


def wait_descriptor(session_id, category, before, after, no_progress_count, interactive=False):
    require(type(session_id) is int, 'host_session_id_required')
    require(category in ('long_task','process_readiness','foreground_query'), 'operation_category_required')
    require(category != 'foreground_query', 'foreground_query_must_not_be_polled')
    observed = progress(before, after)
    count = 0 if observed['progress_confirmed'] else no_progress_count + 1
    if count >= 2 or after.get('state') in ('exited','rejected','timed_out','cancelled','unknown','tool_error'):
        return {'action':'stop_automatic_wait','process_terminated':False,'no_progress_count':count,'observation':observed}
    wait_ms = 5000 if interactive else (10000 if category == 'process_readiness' else 60000)
    require(not interactive, 'interactive_input_needs_explicit_authorized_payload')
    return {'tool':'write_stdin','arguments':{'session_id':session_id,'chars':'','yield_time_ms':wait_ms,'max_output_tokens':6000},
            'exec_yield_time_ms':wait_ms+30000,'one_internal_wait':True,
            'no_progress_count':count,'observation':observed}
