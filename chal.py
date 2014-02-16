import os
import shutil
import json
import pyext
from collections import deque
from tornado.ioloop import IOLoop

TASK_MAX = 4

STATUS_NONE = 0
STATUS_AC = 1
STATUS_WA = 2
STATUS_RE = 3
STATUS_TLE = 4
STATUS_MLE = 5
STATUS_CE = 6
STATUS_ERR = 7

task_runcount = 0
task_queue = deque()

def emit_task(func,*args):
    global task_runcount
    global task_queue

    if task_runcount == TASK_MAX:
        task_queue.appendleft((func,args))
        return

    task_runcount += 1
    func(*args)

def end_task():
    global task_runcount

    def _runqueue():
        global task_runcount
        global task_queue

        while len(task_queue) > 0 and task_runcount < TASK_MAX:
            task_runcount += 1

            func,args = task_queue.pop()
            func(*args)

    task_runcount -= 1
    if task_runcount == (TASK_MAX - 1):
        IOLoop.instance().add_callback(_runqueue)

def emit_test(chal_desc,ws):
    global task_queue

    def _comp_cb(status):
        nonlocal testm

        end_task()

        if status != STATUS_NONE:
            for test_idx in list(testm.keys()):
                IOLoop.instance().add_callback(_end,test_idx,status,0,0)

            return
        
        print('[%.6d] compile pass'%chal_id)

        for test_idx,test in list(testm.items()):
            timelimit = test['timelimit']
            memlimit = test['memlimit']
            metadata = test['metadata']

            testm[test_idx]['remain'] = len(metadata['data'])

            for data_id in metadata['data']:
                _run(chal_id,test_idx,data_id,res_path,timelimit,memlimit)
                
    def _run(chal_id,test_idx,data_id,res_path,timelimit,memlimit):
        emit_task(pyext.chal_run,
                lambda status,runtime,memory : IOLoop.instance().add_callback(
                    _end,test_idx,status,runtime,memory),
                'tmp/run/%d/a.out'%chal_id,
                timelimit,
                memlimit,
                '%s/testdata/%d.in'%(res_path,data_id),
                '%s/testdata/%d.out'%(res_path,data_id))

    def _end(test_idx,status,runtime,memory):
        nonlocal testm

        end_task()

        test = testm[test_idx]
        test['remain'] -= 1
        test['status'] = max(test['status'],status) 
        test['runtime'] += runtime
        test['memory'] = max(test['memory'],memory)

        if test['remain'] > 0:
            return

        testm.pop(test_idx)

        print('[%.6d %.4d] status:%d runtime:%d memory:%d'%(
                chal_id,test_idx,test['status'],test['runtime'],test['memory']))

        ws.write_message(json.dumps({
            'chal_id':chal_id,
            'test_idx':test_idx,
            'state':test['status'],
            'runtime':test['runtime'],
            'memory':test['memory']
        }))

    chal_id = chal_desc['chal_id']
    testl = chal_desc['testl']
    res_path = chal_desc['res_path']
    code_path = chal_desc['code_path']

    typ = testl[0]['comp_type']
    if typ == 'clang++':
        comp_type = 0

    elif typ == 'makefile':
        comp_type = 1

    elif typ == 'g++':
        comp_type = 2

    testm = {}
    for test in testl:
        test['remain'] = 1
        test['status'] = STATUS_NONE
        test['runtime'] = 0
        test['memory'] = 0
        testm[test['test_idx']] = test

    try:
        shutil.rmtree("tmp/run/%d"%chal_id)
    except OSError:
        pass
    os.mkdir("tmp/run/%d"%chal_id)

    emit_task(pyext.chal_comp,
            lambda status : IOLoop.instance().add_callback(_comp_cb,status),
            comp_type,res_path,code_path,"tmp/run/%d/a.out"%chal_id)
