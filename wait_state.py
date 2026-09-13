"""Trusted observations and wait accounting, executed only inside the original command tool."""
import time
from pathlib import Path
from adapter import wait_descriptor
from common import read_json,require,save
from windows_state import FileMutex,observe

TERMINAL={'exited','rejected','timed_out','cancelled','unknown','tool_error'}
def collect(directory,state):
    sample={'execution_id':state['execution_id'],'observed_at_unix':time.time(),'state':state['state'],
            'process':state.get('process',{}),'output':state.get('output',{}),
            'output_record_observed_at_unix':state.get('last_observed_unix')}
    birth_file=directory/'business-process.json'
    if birth_file.is_file():
        birth=read_json(birth_file)
        current=observe(birth['pid'])
        same=birth.get('creation_time') is not None and birth['creation_time']==current.get('creation_time')
        sample['business_observation']=dict(current,same_instance=same)
        if not same:
            sample['business_observation'].update(alive=None,cpu_seconds=None,exit_code=None)
    else:
        sample['business_observation']={'alive':None,'cpu_seconds':None,'exit_code':None,'same_instance':None}
    artifacts={}
    for name,path in state.get('request',{}).get('artifacts',{}).items():
        try:
            stat=Path(path).stat()
            artifacts[name]={'size':stat.st_size,'mtime_ns':stat.st_mtime_ns}
        except FileNotFoundError:
            artifacts[name]={'exists':False}
        except OSError:
            artifacts[name]={'unknown':True}
    sample['artifact_observations']=artifacts
    return sample

def decide(directory,state,query,receipt,policy):
    require(receipt['execution_id']==state['execution_id'] and receipt['request_id']==state['request_id'],'wait_receipt_target_mismatch')
    definition=policy.get('operations',{}).get(state['request']['operation'])
    require(definition is not None and 'wait_category' in definition,'approved_wait_category_missing')
    category=definition['wait_category']
    require(category in ('long_task','process_readiness'),'operation_does_not_support_polling')
    with FileMutex(directory/'wait-state.lock'):
        file=directory/'wait-state.json'
        journal=read_json(file) if file.is_file() else {'execution_id':state['execution_id'],'session_id':receipt['session_id'],'count':0,'previous':None,'queries':{}}
        require(journal['execution_id']==state['execution_id'] and journal['session_id']==receipt['session_id'],'wait_journal_binding_conflict')
        if query['request_id'] in journal['queries']:
            return journal['queries'][query['request_id']]
        after=collect(directory,state)
        if journal['previous'] is None and state['state'] not in TERMINAL:
            ms=60000 if category=='long_task' else 10000
            decision={'tool':'write_stdin','arguments':{'session_id':receipt['session_id'],'chars':'','yield_time_ms':ms,'max_output_tokens':6000},
                      'exec_yield_time_ms':ms+30000,'one_internal_wait':True,'no_progress_count':0,
                      'observation':{'progress_confirmed':False,'reason':'initial_baseline_only','process_alive':after['business_observation']['alive']}}
        else:
            decision=wait_descriptor(receipt['session_id'],category,journal['previous'] or {},after,journal['count'])
        value={'query_request_id':query['request_id'],'execution_id':state['execution_id'],'target_request_id':state['request_id'],
               'state':state['state'],'decision':decision,'before':journal['previous'],'after':after,
               'counts_source':'executor_wait_journal','observations_source':'original_tool_process_and_record_observation'}
        journal.update(previous=after,count=decision['no_progress_count'])
        journal['queries'][query['request_id']]=value
        save(file,journal)
        return value
