import os
import json
from tornado import gen, concurrent
from tornado.ioloop import IOLoop, PollIOLoop
from tornado.web import Application, RequestHandler
from tornado.websocket import WebSocketHandler
import PyExt
from StdChal import StdChal


class UVIOLoop(PollIOLoop):
    def initialize(self, **kwargs):
        super().initialize(impl = PyExt.UvPoll(), **kwargs)


@gen.coroutine
def test(chal_id):
    chal = StdChal(chal_id, 'lib/test.cpp', 'g++', [
        {
            'in':'lib/in.txt',
            'ans':'lib/out.txt',
            'timelimit': 500,
            'memlimit': 128 * 1024 * 1024,
        }
    ] * 1)
    ret = yield chal.start()
    print(ret)


class JudgeHandler(WebSocketHandler): 
    def open(self): 
        pass 
         
    @gen.coroutine
    def on_message(self,msg): 
        obj = json.loads(msg,'utf-8')
        chal_id = obj['chal_id']
        code_path = '/srv/nfs' + obj['code_path'][4:]
        test_list = obj['testl']
        res_path = '/srv/nfs' + obj['res_path'][4:]

        test_paramlist = list()
        comp_type = test_list[0]['comp_type']
        assert(comp_type in ['g++', 'clang++', 'makefile'])

        for test in test_list:
            assert(test['comp_type'] == comp_type)
            assert(test['check_type'] == 'diff')
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

        print(code_path)
        print(test_paramlist)
        chal = StdChal(code_path, comp_type, res_path, test_paramlist)
        result_list = yield chal.start()

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

            self.write_message(json.dumps({
                'chal_id': chal_id,
                'test_idx': test_idx,
                'state': total_status,
                'runtime': total_runtime,
                'memory': total_mem,
            }))

    def on_close(self): 
        pass


def main():
    PyExt.init()
    StdChal.init()
    IOLoop.configure(UVIOLoop)

    app = Application([
        (r'/judge', JudgeHandler),
    ])
    app.listen(2501)

    IOLoop.instance().start()


if __name__ == '__main__':
    main()
