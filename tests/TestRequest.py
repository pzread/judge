'''Request API unittest module.'''

import json
from tornado import testing, httpclient
from tornado.ioloop import IOLoop, PollIOLoop
import PyExt
import Privilege
import Server
from StdChal import StdChal, STATUS_AC


class EvIOLoop(PollIOLoop):
    '''Tornado compatible ioloop interface.'''

    def initialize(self, **kwargs):
        '''Initialize.'''

        super().initialize(impl=PyExt.EvPoll(), **kwargs)


class RequestCase(testing.AsyncTestCase):
    '''Run request API tests.'''

    def __init__(self, *args):
        Privilege.init()
        PyExt.init()
        StdChal.init()
        IOLoop.configure(EvIOLoop)

        Server.init_socket_server()

        super().__init__(*args)

    def get_new_ioloop(self):
        return IOLoop().instance()

    @testing.gen_test(timeout=60)
    def test_stdchal(self):
        '''Test g++, A + B problems.'''

        conn = httpclient.AsyncHTTPClient()
        resp = yield conn.fetch(httpclient.HTTPRequest(
            'http://localhost:2501/reqjudge',
            method='POST',
            body=json.dumps({
                'chal_id': 573,
                'code_path': 'tests/testdata/test.cpp',
                'res_path': 'tests/testdata/res',
                'comp_type': 'g++',
                'check_type': 'diff',
                'metadata': {},
                'test': [{
                    'test_idx': 0,
                    'timelimit': 10000,
                    'memlimit': 256 * 1024 * 1024,
                    'metadata': {
                        'data': [0],
                    },
                }],
            })))
        obj = json.loads(resp.body.decode('utf-8'))
        self.assertEqual(obj['chal_id'], 573)
        result_list = obj['result']
        self.assertEqual(len(result_list), 1)
        for result in result_list:
            self.assertEqual(result['state'], STATUS_AC)
        conn.close()
        
        conn = httpclient.AsyncHTTPClient()
        resp = yield conn.fetch(httpclient.HTTPRequest(
            'http://localhost:2501/reqjudge',
            method='POST',
            body=json.dumps({
                'chal_id': 574,
                'code_path': 'tests/testdata/testx.cpp',
                'res_path': 'tests/testdata/res',
                'comp_type': 'g++',
                'check_type': 'diff',
                'metadata': {},
                'test': [{
                    'test_idx': 0,
                    'timelimit': 10000,
                    'memlimit': 256 * 1024 * 1024,
                    'metadata': {
                        'data': [0],
                    },
                }],
            })))
        obj = json.loads(resp.body.decode('utf-8'))
        self.assertEqual(obj['chal_id'], 574)
        result_list = obj['result']
        self.assertEqual(result_list, None)
        conn.close()
