import tornado.web
import pyext

last_chal_id = 0

def emit_chal():
    global last_chal_id

    last_chal_id += 1 
    chalid = last_chal_id;
    
    pyext.chal_comp(chalid)

def comp_callback(chalid,status):
    print(status)

class ChalAddHandler(tornado.web.RequestHandler):
    def get(self):
        emit_chal()

        self.write('Hello World')
