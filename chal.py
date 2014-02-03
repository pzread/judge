import tornado.web
import pyext

STATUS_NONE = 0
STATUS_AC = 1
STATUS_WA = 2
STATUS_RE = 3
STATUS_TLE = 4
STATUS_MLE = 5
STATUS_CE = 6
STATUS_ERR = 7

last_chal_id = 0

def emit_chal():
    global last_chal_id

    def _comp_cb(status):
        if status != STATUS_NONE:
            _end(status,0,0)
            return
        
        print('[%.6d] compile pass'%chalid)
        pyext.chal_run(_end,"tmp/run/a.out",timelimit,memlimit)

    def _end(status,runtime,memory):
        print('[%.6d] status:%d runtime:%d memory:%d'%(
                chalid,status,runtime,memory))

    last_chal_id += 1 
    chalid = last_chal_id;

    timelimit = 4000
    memlimit = 65536 * 1024
    
    pyext.chal_comp(_comp_cb,"tmp/code/main.cpp","tmp/run/a.out")

class ChalAddHandler(tornado.web.RequestHandler):
    def get(self):
        emit_chal()

        self.write('Hello World')
