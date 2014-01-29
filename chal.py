import tornado.web
import pyext

class ChalAddHandler(tornado.web.RequestHandler):
    def get(self):
        pyext.chal_add()
        self.write('Hello World')
