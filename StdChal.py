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
    null_fd = None

    def init():
        try:
            shutil.rmtree('container/standard/home')
        except FileNotFoundError:
            pass
        os.mkdir('container/standard/home', mode=0o711)

        StdChal.null_fd = os.open('/dev/null', os.O_RDWR | os.O_CLOEXEC)

    def __init__(self, chal_id, code_path, comp_typ, test_list):
        self.chal_id = chal_id
        self.code_path = code_path
        self.comp_typ = comp_typ
        self.test_list = test_list
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

        for test in self.test_list:
            print(test)
            ret = yield self.judge_diff(test['in'], test['ans'],
                test['timelimit'], test['memlimit'])
            print(ret)

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
                './a.cpp'
            ],
            [
                'PATH=/usr/bin',
                'TMPDIR=/home/%d/compile'%self.chal_id
            ],
            StdChal.null_fd, StdChal.null_fd, StdChal.null_fd,
            '/home/%d/compile'%self.chal_id, 'container/standard',
            self.compile_uid, self.compile_gid, 1200, 256 * 1024 * 1024,
            PyExt.RESTRICT_LEVEL_LOW)

        PyExt.start_task(task_id, _done_cb)

    @concurrent.return_future
    def judge_diff(self, in_path, ans_path, timelimit, memlimit, callback):
        infile = open(in_path, 'rb')
        ansfile = open(ans_path, 'rb')
        inpipe_fd = os.pipe2(os.O_CLOEXEC)
        outpipe_fd = os.pipe2(os.O_CLOEXEC)
        result_stat = None
        result_pass = None

        def _done_cb(task_id, stat):
            nonlocal result_stat
            nonlocal result_pass

            result_stat = (stat['utime'], stat['peakmem'], stat['detect_error'])
            if result_pass is not None:
                callback((result_pass, result_stat))

        def _diff_in(fd, events):
            nonlocal inpipe_fd
            nonlocal infile

            end_flag = False
            if events & IOLoop.WRITE:
                while True:
                    data = infile.read(4096)
                    if len(data) == 0:
                        end_flag = True
                        break
                    try:
                        ret = os.write(inpipe_fd[1], data) 
                    except BlockingIOError:
                        infile.seek(-len(data), 1)
                        break
                    if ret == 0:
                        end_flag = True
                        break
                    if ret < len(data):
                        infile.seek(-(len(data) - ret), 1)

            if (events & IOLoop.ERROR) or end_flag:
                IOLoop.instance().remove_handler(fd)
                os.close(inpipe_fd[1])
                infile.close()

        def _diff_out(fd, events):
            nonlocal outpipe_fd
            nonlocal ansfile
            nonlocal result_stat
            nonlocal result_pass

            end_flag = False
            if events & IOLoop.READ:
                while True:
                    try:
                        data = os.read(outpipe_fd[0], 65536)
                    except BlockingIOError:
                        break
                    ansdata = ansfile.read(len(data))
                    if data != ansdata:
                        result_pass = False
                        end_flag = True
                        break
                    if len(ansdata) == 0:
                        result_pass = True
                        end_flag = True
                        break

            if (events & IOLoop.ERROR) or end_flag:
                IOLoop.instance().remove_handler(fd)
                os.close(outpipe_fd[0])
                ansfile.close()

                if result_stat is not None:
                    callback((result_pass, result_stat))

        StdChal.last_judge_uid += 1
        judge_uid = StdChal.last_judge_uid
        judge_gid = judge_uid

        judge_path = self.chal_path + '/run_%d'%judge_uid
        os.mkdir(judge_path, mode=0o750)
        os.chown(judge_path, judge_uid, judge_gid)
        shutil.copyfile(self.chal_path + '/compile/a.out',
            judge_path + '/a.out')
        os.chown(judge_path + '/a.out', judge_uid, judge_gid)
        os.chmod(judge_path + '/a.out', 0o700)

        task_id = PyExt.create_task('/home/%d/run_%d/a.out'%(
                self.chal_id, judge_uid),
            [],
            [],
            inpipe_fd[0], outpipe_fd[1], outpipe_fd[1],
            '/home/%d/run_%d'%(self.chal_id, judge_uid), 'container/standard',
            judge_uid, judge_gid, timelimit, memlimit,
            PyExt.RESTRICT_LEVEL_HIGH)

        PyExt.start_task(task_id, _done_cb)

        os.close(inpipe_fd[0])
        os.close(outpipe_fd[1])
        IOLoop.instance().add_handler(inpipe_fd[1], _diff_in,
            IOLoop.WRITE | IOLoop.ERROR)
        IOLoop.instance().add_handler(outpipe_fd[0], _diff_out,
            IOLoop.READ | IOLoop.ERROR)
