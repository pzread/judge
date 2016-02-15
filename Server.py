from tornado.ioloop import IOLoop, PollIOLoop
from tornado.web import Application, RequestHandler
import PyExt
from StdChal import StdChal


class IndexHandler(RequestHandler):
    def get(self):
        self.write('Index')


class UVIOLoop(PollIOLoop):
    def initialize(self, **kwargs):
        super().initialize(impl = PyExt.UvPoll(), **kwargs)


def test():
    task_id = PyExt.create_task('/usr/bin/g++',
        ['-o', '/tmp/a.out', '/tmp/test.cpp'],
        ['PATH=/usr/bin'],
        '/tmp', 'container/standard',
        11000, 10000, 1200, 10 * 1024 * 1024)

    PyExt.start_task(task_id, lambda x: test())


def main():
    PyExt.init()
    StdChal.init()
    IOLoop.configure(UVIOLoop)
    app = Application([
        (r'/', IndexHandler),
    ])
    app.listen(6000)
    IOLoop.instance().add_callback(test)
    IOLoop.instance().start()


if __name__ == '__main__':
    main()
