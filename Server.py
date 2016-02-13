import PyExt
from tornado.ioloop import IOLoop, PollIOLoop
from tornado.web import Application, RequestHandler


class IndexHandler(RequestHandler):
    def get(self):
        self.write('Index')
        PyExt.create_task('/bin/ls')


class UVIOLoop(PollIOLoop):
    def initialize(self, **kwargs):
        super().initialize(impl = PyExt.UvPoll(), **kwargs)


def main():
    PyExt.init()
    IOLoop.configure(UVIOLoop)

    app = Application([
        (r'/', IndexHandler),
    ])
    app.listen(8000)
    IOLoop.instance().start()


if __name__ == '__main__':
    main()
