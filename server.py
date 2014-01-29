import tornado.ioloop
import tornado.web

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

if __name__ == '__main__':
    tornado.ioloop.IOLoop.configure(EPollIOLoop)

    app = tornado.web.Application([
        ("/add_chal",chal.ChalAddHandler),
    ])
    app.listen(2501)

    tornado.ioloop.IOLoop.instance().start()
