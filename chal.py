import pyext

STATUS_NONE = 0
STATUS_AC = 1
STATUS_WA = 2
STATUS_RE = 3
STATUS_TLE = 4
STATUS_MLE = 5
STATUS_CE = 6
STATUS_ERR = 7

def emit_test(chal_desc):
    def _comp_cb(status):
        if status != STATUS_NONE:
            _end(status,0,0)
            return
        
        print('[%.6d] compile pass'%chal_id)
        pyext.chal_run(_end,"tmp/run/%d/a.out"%chal_id,timelimit,memlimit)

    def _end(status,runtime,memory):
        print('[%.6d] status:%d runtime:%d memory:%d'%(
                chal_id,status,runtime,memory))

    chal_id = chal_desc['chal_id']
    timelimit = chal_desc['timelimit']
    memlimit = chal_desc['memlimit'] * 1024
    code_path = chal_desc['code_path']
    res_path = chal_desc['res_path']

    print(code_path)

    pyext.chal_comp(_comp_cb,code_path,"tmp/run/%d/a.out"%chal_id)
