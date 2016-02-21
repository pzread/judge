import os
import json
from collections import deque
from tornado import gen, concurrent
from tornado.ioloop import IOLoop, PollIOLoop
from tornado.web import Application, RequestHandler
import PyExt
import Privilege
import Config
from StdChal import StdChal


class UVIOLoop(PollIOLoop):
    def initialize(self, **kwargs):
        super().initialize(impl = PyExt.UvPoll(), **kwargs)


@gen.coroutine
def test():
    chal = StdChal(1, 'lib/test.cpp', 'g++', 'lib', [
        {
            'in': 'lib/in.txt',
            'ans': 'lib/out.txt',
            'timelimit': 2000,
            'memlimit': 256 * 1024 * 1024,
        }    
    ])
    result_list = yield chal.start()
    print(result_list)


def main():
    Privilege.init()
    PyExt.init()
    StdChal.init()
    IOLoop.configure(UVIOLoop)

    IOLoop.instance().add_callback(test)

    IOLoop.instance().start()


if __name__ == '__main__':
    main()
