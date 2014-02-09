import os
import re
import json
import uuid
import tornado.ioloop
import tornado.web
from tornado.websocket import WebSocketHandler
from tornado.gen import coroutine

import pyext
import chal

class EPollIOLoop(tornado.ioloop.PollIOLoop):
    class _epoll:
        def __init__(self):
            self._epfd = pyext.epoll_create()

        def register(self,fd,events):
            pyext.epoll_register(self._epfd,fd,events)

        def unregister(self,fd):
            pyext.epoll_unregister(self._epfd,fd)

        def modify(self,fd,events):
            pyext.epoll_modify(self._epfd,fd,events)

        def poll(self,timeout = -1,maxevents = -1):
            if timeout != -1:
                timeout = round(timeout * 1000)

            return pyext.epoll_poll(self._epfd,timeout)

        def close(self):
            pyext.epoll_free(self._epfd)

    def initialize(self,**kwargs):
        super(EPollIOLoop,self).initialize(impl = self._epoll(), **kwargs)

class DescHandler(tornado.websocket.WebSocketHandler):
    def open(self):
        pass

    def on_message(self,msg):
        desc = json.loads(msg,'utf-8')
        uri = desc['uri']
        path = re.search('^dsd://(.*)',uri).group(1)

        if path == 'judge/chal_add':
            pass

    def on_close(self):
        pass

class BinaHandler(tornado.websocket.WebSocketHandler):
    def open(self):
        self.remain = 0

    def on_message(self,msg):
        if self.remain > 0:
            self.outf.write(msg)
            self.remain -= len(msg)

            if self.remain == 0:
                self.outf.close()

        else:
            bina = json.loads(msg,'utf-8')
            uri = bina['uri']
            path = re.search('^dsb://(.*)',uri).group(1)
            bina_id = str(uuid.UUID(bina['bina_id']))
            size = bina['bina_size']

            self.remain = size
            self.outf = open(bina_id,'wb')

    def on_close(self):
        pass

class TestChalHandler(tornado.web.RequestHandler):
    @coroutine
    def get(self):
        desc = {
            'uri':'dsd://judge/chal_add',
            'chal_id':1,
            'test':[
                {
                    'test_id':0,
                    'timelimit':4000,
                    'memlimit':65536 * 1035,
                    'testdata':'asdf'
                },
            ],
        }

        f = open('in','rb')
        size = os.stat('in').st_size
        bina = {
            'uri':'dsb://judge/chal_add',
            'bina_id':str(uuid.uuid1()),
            'bina_size':size,
        }

        ws = yield tornado.websocket.websocket_connect('ws://localhost:2501/dsb')
        ws.write_message(json.dumps(bina))

        while True:
            ret = f.read(65536)
            if len(ret) == 0:
                break

            ws.write_message(ret,binary = True)

        f.close()

class JudgeHandler(WebSocketHandler):
    def open(self):
        pass

    def on_message(self,msg):
        chal.emit_test(json.loads(msg,'utf-8'),self)

    def on_close(self):
        pass

if __name__ == '__main__':
    tornado.ioloop.IOLoop.configure(EPollIOLoop)

    app = tornado.web.Application([
        ('/judge',JudgeHandler),
    ])
    app.listen(2501)

    tornado.ioloop.IOLoop.instance().start()
