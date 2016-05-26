'''Server module.

Handle and response challenge requests from the frontend server.

'''

import sys
import json
import traceback
from collections import deque
from tornado import gen, concurrent
from tornado.ioloop import IOLoop, PollIOLoop
from tornado.web import Application, RequestHandler
from tornado.websocket import WebSocketHandler
import PyExt
import Privilege
import Config
from StdChal import StdChal


class EvIOLoop(PollIOLoop):
    '''Tornado compatible ioloop interface.'''

    def initialize(self, **kwargs):
        '''Initialize.'''

        super().initialize(impl=PyExt.EvPoll(), **kwargs)


class JudgeDispatcher:
    '''Judge request dispatcher.

    Static attributes:
        chal_running_count (int): Number of current running challenges.
        chal_queue (deque): Pending challenges.

    '''

    chal_running_count = 0
    chal_queue = deque()

    @staticmethod
    @gen.coroutine
    def start_chal(obj, callback):
        '''Start a challenge.

        Check the challenge config, issue judge tasks, then report the result.

        Args:
            obj (dict): Challenge config.
            callback: Challenge callback.

        Returns:
            None

        '''

        # The worst exception, there is no chal_id in the obj.
        chal_id = None
        try:
            chal_id = obj['chal_id']
            code_path = obj['code_path']
            res_path = obj['res_path']
            test_list = obj['test']
            metadata = obj['metadata']
            comp_type = obj['comp_type']
            check_type = obj['check_type']

            test_paramlist = list()
            assert comp_type in ['g++', 'clang++', 'makefile', 'python3']
            assert check_type in ['diff', 'ioredir']

            for test in test_list:
                test_idx = test['test_idx']
                memlimit = test['memlimit']
                timelimit = test['timelimit']
                data_ids = test['metadata']['data']
                for data_id in data_ids:
                    test_paramlist.append({
                        'in': res_path + '/testdata/%d.in'%data_id,
                        'ans': res_path + '/testdata/%d.out'%data_id,
                        'timelimit': timelimit,
                        'memlimit': memlimit,
                    })

            chal = StdChal(chal_id, code_path, comp_type, check_type, \
                res_path, test_paramlist, metadata)
            result_list, verdict = yield chal.start()

            result = []
            idx = 0
            for test in test_list:
                test_idx = test['test_idx']
                data_ids = test['metadata']['data']
                total_runtime = 0
                total_mem = 0
                total_status = 0
                for data_id in data_ids:
                    runtime, peakmem, status = result_list[idx]
                    total_runtime += runtime
                    total_mem += peakmem
                    total_status = max(total_status, status)
                    idx += 1

                result.append({
                    'test_idx': test_idx,
                    'state': total_status,
                    'runtime': total_runtime,
                    'peakmem': total_mem,
                    'verdict': ''
                })

            callback({
                'chal_id': chal_id,
                'verdict': verdict,
                'result': result,
            })

        except Exception:
            traceback.print_exception(*sys.exc_info())
            callback({
                'chal_id': chal_id,
                'verdict': None,
                'result': None,
            })

        finally:
            JudgeDispatcher.chal_running_count -= 1
            JudgeDispatcher.emit_chal()

    @staticmethod
    def emit_chal(obj=None, callback=None):
        '''Emit a challenge to the queue and trigger the start_chal.

        Args:
            obj (dict, optional): Challenge config.
            callback: Challange callback.

        Returns:
            None

        '''

        if obj is not None:
            JudgeDispatcher.chal_queue.append((obj, callback))

        while (len(JudgeDispatcher.chal_queue) > 0
            and JudgeDispatcher.chal_running_count < Config.TASK_MAXCONCURRENT):
            chal = JudgeDispatcher.chal_queue.popleft()
            JudgeDispatcher.chal_running_count += 1
            IOLoop.instance().add_callback(JudgeDispatcher.start_chal, *chal)


class WebSocketClient(WebSocketHandler):
    '''Websocket request handler.'''

    def open(self):
        '''Handle open event'''

        print('Frontend connected')

    def on_message(self, msg):
        '''Handle message event'''

        obj = json.loads(msg, 'utf-8')
        JudgeDispatcher.emit_chal(obj,
            lambda res: self.write_message(json.dumps(res)))

    def on_close(self):
        '''Handle close event'''

        print('Frontend disconnected')


class RequestClient(RequestHandler):
    '''HTTP request handler.'''

    @concurrent.return_future
    def post(self, callback):
        '''Handle POST request'''

        def _chal_cb(res):
            self.write(res)
            callback()

        obj = json.loads(self.request.body.decode('utf-8'))
        JudgeDispatcher.emit_chal(obj, _chal_cb)


def init_websocket_server():
    '''Initialize websocket server.'''

    app = Application([
        (r'/judge', WebSocketClient),
        (r'/reqjudge', RequestClient),
    ])
    app.listen(2501)


def main():
    '''Main function.'''

    Privilege.init()
    PyExt.init()
    StdChal.init()
    IOLoop.configure(EvIOLoop)

    init_websocket_server()

    IOLoop.instance().start()


if __name__ == '__main__':
    main()
