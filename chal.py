import os
import json
import pyext

STATUS_NONE = 0
STATUS_AC = 1
STATUS_WA = 2
STATUS_RE = 3
STATUS_TLE = 4
STATUS_MLE = 5
STATUS_CE = 6
STATUS_ERR = 7

def emit_test(chal_desc,ws):
    def _comp_cb(status):
        if status != STATUS_NONE:
            for test in tests:
                _end(test['test_idx'],status,0,0)

            return
        
        print('[%.6d] compile pass'%chal_id)

        for test in tests:
            test_idx = test['test_idx']
            data = test['data']

            for data_id in data:
                pyext.chal_run(lambda status,runtime,memory : _end(
                    test_idx,status,runtime,memory),
                    "tmp/run/%d/a.out"%chal_id,
                    timelimit,memlimit,
                    '%s/%d.in'%(res_path,data_id),
                    '%s/%d.out'%(res_path,data_id))

    def _end(test_idx,status,runtime,memory):
        nonlocal test_map

        test = test_map[test_idx]
        test['remain'] -= 1
        test['status'] = max(test['status'],status) 
        test['runtime'] += runtime
        test['memory'] = max(test['memory'],memory)
        if test['remain'] > 0:
            return

        test_map.pop(test_idx)

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
    timelimit = chal_desc['timelimit']
    memlimit = chal_desc['memlimit'] * 1024
    tests = chal_desc['tests']
    code_path = chal_desc['code_path']
    res_path = chal_desc['res_path']

    try:
        os.removedirs("tmp/run/%d"%chal_id)
        os.mkdir("tmp/run/%d"%chal_id)

    except OSError:
        pass
    
    test_map = {}
    for test in tests:
        test_map[test['test_idx']] = {
            'remain':len(test['data']),
            'status':STATUS_NONE,
            'runtime':0,
            'memory':0
        }

    pyext.chal_comp(_comp_cb,code_path,"tmp/run/%d/a.out"%chal_id)
