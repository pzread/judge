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
        nonlocal testm

        if status != STATUS_NONE:
            for test_idx in testm.keys():
                _end(test_idx,status,0,0)

            return
        
        print('[%.6d] compile pass'%chal_id)

        for test_idx,test in testm.items():
            timelimit = test['timelimit']
            memlimit = test['memlimit']
            metadata = json.loads(test['metadata'],'utf-8')

            testm[test_idx]['remain'] = len(metadata['data'])

            for data_id in metadata['data']:
                _run(test_idx,'tmp/run/%d/a.out'%chal_id,
                        timelimit,memlimit,
                        '%s/testdata/%d.in'%(res_path,data_id),
                        '%s/testdata/%d.out'%(res_path,data_id))
   
    def _run(test_idx,run_path,timelimit,memlimit,in_path,ans_path):
        pyext.chal_run(lambda status,runtime,memory : _end(
            test_idx,status,runtime,memory),run_path,
            timelimit,memlimit,in_path,ans_path)

    def _end(test_idx,status,runtime,memory):
        nonlocal testm

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

    if testl[0]['comp_type'] == 'clang++':
        comp_type = 0

    elif testl[0]['comp_type'] == 'makefile':
        comp_type = 1

    testm = {}
    for test in testl:
        test['remain'] = 1
        test['status'] = STATUS_NONE
        test['runtime'] = 0
        test['memory'] = 0
        testm[test['test_idx']] = test

    try:
        os.removedirs("tmp/run/%d"%chal_id)
    except OSError:
        pass
    os.mkdir("tmp/run/%d"%chal_id)

    pyext.chal_comp(_comp_cb,comp_type,res_path,code_path,
            "tmp/run/%d/a.out"%chal_id)
