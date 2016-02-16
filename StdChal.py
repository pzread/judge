import os
import shutil
from tornado import gen
from tornado import concurrent
from tornado.ioloop import IOLoop
import PyExt
import Config


class StdChal:
    last_compile_uid = Config.CONTAINER_STANDARD_UID_BASE
    last_judge_uid = Config.CONTAINER_RESTRICT_UID_BASE

    def init():
        try:
            shutil.rmtree('container/standard/home')
        except FileNotFoundError:
            pass
        os.mkdir('container/standard/home', mode=0o711)

    def __init__(self, chal_id, code_path, comp_typ, param_list):
        self.chal_id = chal_id
        self.code_path = code_path
        self.comp_typ = comp_typ
        self.param_list = param_list
        self.chal_path = None

        StdChal.last_compile_uid += 1
        self.compile_uid = StdChal.last_compile_uid
        self.compile_gid = self.compile_uid

    @gen.coroutine
    def start(self):
        self.chal_path = 'container/standard/home/%d'%self.chal_id
        os.mkdir(self.chal_path, mode=0o711)

        if self.comp_typ == 'g++':
            ret = yield self.comp_gxx()

        if ret != PyExt.DETECT_NONE:
            shutil.rmtree(self.chal_path)
            return {
                'status': 5,        
            }

        shutil.rmtree(self.chal_path)
            
    @concurrent.return_future
    def comp_gxx(self, callback):
        def _done_cb(task_id, stat):
            callback(stat['detect_error'])

        compile_path = self.chal_path + '/compile'
        os.mkdir(compile_path, mode=0o750)
        os.chown(compile_path, self.compile_uid, self.compile_gid)
        os.link(self.code_path, compile_path + '/a.cpp')

        task_id = PyExt.create_task('/usr/bin/g++',
            [
                '-O2',
                '-o', './a.out',
                './ai.cpp'
            ],
            [
                'PATH=/usr/bin',
                'TMPDIR=/home/%d/compile'%self.chal_id
            ],
            '/home/%d/compile'%self.chal_id, 'container/standard',
            self.compile_uid, self.compile_gid, 1200, 256 * 1024 * 1024,
            PyExt.RESTRICT_LEVEL_LOW)

        PyExt.start_task(task_id, _done_cb)
