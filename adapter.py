"""Pure host adapter. No subprocess, business file access, or permission decisions."""
from common import require


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
