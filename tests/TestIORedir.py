'''I/O redirect special judge unittest module.'''

from tornado import testing
from tornado.ioloop import IOLoop, PollIOLoop
import PyExt
import Privilege
from StdChal import StdChal, STATUS_AC, STATUS_WA


class EvIOLoop(PollIOLoop):
    '''Tornado compatible ioloop interface.'''

    def initialize(self, **kwargs):
        '''Initialize.'''

        super().initialize(impl=PyExt.EvPoll(), **kwargs)


class IORedirJudgeCase(testing.AsyncTestCase):
    '''Run I/O redirect special judge tests.'''

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
        '''Test g++, I/O redirect special judge.'''

        chal = StdChal(1, 'tests/testdata/test.cpp', 'g++', 'ioredir', \
            'tests/testdata/res', [
                {
                    'in': 'tests/testdata/res/testdata/0.in',
                    'ans': 'tests/testdata/res/testdata/0.out',
                    'timelimit': 10000,
                    'memlimit': 256 * 1024 * 1024,
                }
            ] * 4, {
                'redir_test': {
                    "testin": 0,
                    "testout": -1,
                    "pipein": -1,
                    "pipeout": 1,
                },
                'redir_check': {
                    "testin": -1,
                    "ansin": 2,
                    "pipein": -1,
                    "pipeout": 0,
                }
            } \
        )
        result_list = yield chal.start()
        self.assertEqual(len(result_list), 4)
        for result in result_list:
            _, _, status, verdict = result
            self.assertEqual(status, STATUS_AC)
            self.assertEqual(verdict, 'Passed\n')

        chal = StdChal(2, 'tests/testdata/testwa.cpp', 'g++', 'ioredir', \
            'tests/testdata/res', [
                {
                    'in': 'tests/testdata/res/testdata/0.in',
                    'ans': 'tests/testdata/res/testdata/0.out',
                    'timelimit': 10000,
                    'memlimit': 256 * 1024 * 1024,
                }
            ], {
                'redir_test': {
                    "testin": 0,
                    "testout": -1,
                    "pipein": -1,
                    "pipeout": 1,
                },
                'redir_check': {
                    "testin": -1,
                    "ansin": 2,
                    "pipein": -1,
                    "pipeout": 0,
                }
            } \
        )
        result_list = yield chal.start()
        self.assertEqual(len(result_list), 1)
        _, _, status, verdict = result_list[0]
        self.assertEqual(status, STATUS_WA)
        self.assertEqual(verdict, 'Diff\n12\n\n7\n\n')
