'''Unittest module.'''

from tornado import testing
from tornado.ioloop import IOLoop, PollIOLoop
import PyExt
import Privilege
import StdChal
from StdChal import StdChal


class EvIOLoop(PollIOLoop):
    '''Tornado compatible ioloop interface.'''

    def initialize(self, **kwargs):
        '''Initialize.'''

        super().initialize(impl=PyExt.EvPoll(), **kwargs)


class StdChalCase(testing.AsyncTestCase):
    '''Run all tests.'''

    def __init__(self, *args):
        Privilege.init()
        PyExt.init()
        StdChal.init()

        super().__init__(*args)

    def get_new_ioloop(self):
        IOLoop.configure(EvIOLoop)
        return IOLoop().instance()

    @testing.gen_test(timeout=60)
    def test_stdchal(self):
        '''Test g++, A + B problems.'''

        chal = StdChal(1, 'tests/testdata/test.cpp', 'g++', 'tests/testdata', [
            {
                'in': 'tests/testdata/in.txt',
                'ans': 'tests/testdata/ans.txt',
                'timelimit': 10000,
                'memlimit': 256 * 1024 * 1024,
            }
        ] * 4)
        result_list = yield chal.start()
        for result in result_list:
            _, _, status = result
            self.assertEqual(status, StdChal.STATUS_AC)
