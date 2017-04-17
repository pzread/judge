'''Compile unittest module.'''

from tornado import testing
from tornado.ioloop import IOLoop, PollIOLoop
import PyExt
import Privilege
from StdChal import StdChal, STATUS_CE


class EvIOLoop(PollIOLoop):
    '''Tornado compatible ioloop interface.'''

    def initialize(self, **kwargs):
        '''Initialize.'''

        super().initialize(impl=PyExt.EvPoll(), **kwargs)


class CompileCase(testing.AsyncTestCase):
    '''Run compile tests.'''

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

        chal = StdChal(1, 'tests/testdata/testce.cpp', 'g++', 'diff', \
            'tests/testdata/res', \
            [
                {
                    'in': 'tests/testdata/res/testdata/0.in',
                    'ans': 'tests/testdata/res/testdata/0.out',
                    'timelimit': 10000,
                    'memlimit': 256 * 1024 * 1024,
                }
            ] * 4, {})
        result_list = yield chal.start()
        self.assertEqual(len(result_list), 4)
        for result in result_list:
            _, _, status, verdict = result
            self.assertNotEqual(verdict, '')
            self.assertEqual(status, STATUS_CE)

