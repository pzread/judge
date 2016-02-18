import os
import shutil
import mmap
from tornado import gen, concurrent, process
from tornado.ioloop import IOLoop
import PyExt
import Config


STATUS_NONE = 0 
STATUS_AC = 1 
STATUS_WA = 2 
STATUS_RE = 3 
STATUS_TLE = 4 
STATUS_MLE = 5 
STATUS_CE = 6 
STATUS_ERR = 7 


class StdChal:
    last_uniqid = 0
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

    def __init__(self, code_path, comp_typ, res_path, test_list):
        StdChal.last_uniqid += 1
        self.uniqid = StdChal.last_uniqid
        self.code_path = code_path
        self.res_path = res_path
        self.comp_typ = comp_typ
        self.test_list = test_list
        self.chal_path = None

        StdChal.last_compile_uid += 1
        self.compile_uid = StdChal.last_compile_uid
        self.compile_gid = self.compile_uid

    @gen.coroutine
    def start(self):
        self.chal_path = 'container/standard/home/%d'%self.uniqid
        os.mkdir(self.chal_path, mode=0o711)

        if self.comp_typ in ['g++', 'clang++']:
            ret = yield self.comp_cxx()

        elif self.comp_typ == 'makefile':
            ret = yield self.comp_make()

        if ret != PyExt.DETECT_NONE:
            shutil.rmtree(self.chal_path)
            return [(0, 0, STATUS_CE)] * len(self.test_list)

        prefetch_proc = []
        for test in self.test_list:
            prefetch_proc.append(process.Subprocess(
                ['./Prefetch.py', test['in']],
                stdout=process.Subprocess.STREAM))
            prefetch_proc.append(process.Subprocess(
                ['./Prefetch.py', test['ans']],
                stdout=process.Subprocess.STREAM))

        prefetch_future = []
        for proc in prefetch_proc:
            prefetch_future.append(proc.stdout.read_bytes(2))
        yield gen.multi(prefetch_future)

        test_future = []
        for test in self.test_list:
            test_future.append(self.judge_diff(test['in'], test['ans'],
                test['timelimit'], test['memlimit']))

        test_result = yield gen.multi(test_future)
        ret_result = list()
        for result in test_result:
            test_pass, data = result
            runtime, peakmem, error = data
            status = STATUS_ERR
            if error == PyExt.DETECT_NONE:
                if test_pass == True:
                    status = STATUS_AC                   
                else:
                    status = STATUS_WA
            elif error == PyExt.DETECT_OOM:
                status = STATUS_MLE
            elif error == PyExt.DETECT_TIMEOUT \
                or error == PyExt.DETECT_FORCETIMEOUT:
                status = STATUS_TLE
            elif error == PyExt.DETECT_EXITERR:
                status = STATUS_RE
            else:
                status = STATUS_ERR
            ret_result.append((runtime, peakmem, status))

        shutil.rmtree(self.chal_path)
        return ret_result
            
    @concurrent.return_future
    def comp_cxx(self, callback):
        def _done_cb(task_id, stat):
            callback(stat['detect_error'])

        compile_path = self.chal_path + '/compile'
        os.mkdir(compile_path, mode=0o750)
        os.chown(compile_path, self.compile_uid, self.compile_gid)
        shutil.copyfile(self.code_path, compile_path + '/test.cpp',
            follow_symlinks=False)

        if self.comp_typ == 'g++':
            compiler = '/usr/bin/g++'
        elif self.comp_typ == 'clang++':
            compiler = '/usr/bin/clang++'

        task_id = PyExt.create_task(compiler,
            [
                '-O2',
                '-std=c++14',
                '-o', './a.out',
                './test.cpp',
            ],
            [
                'PATH=/usr/bin',
                'TMPDIR=/home/%d/compile'%self.uniqid,
            ],
            StdChal.null_fd, StdChal.null_fd, StdChal.null_fd,
            '/home/%d/compile'%self.uniqid, 'container/standard',
            self.compile_uid, self.compile_gid, 60000, 256 * 1024 * 1024,
            PyExt.RESTRICT_LEVEL_LOW)

        PyExt.start_task(task_id, _done_cb)

    @concurrent.return_future
    def comp_make(self, callback):
        def _copy_fn(src, dst, follow_symlinks=True):
            shutil.copy(src, dst, follow_symlinks=False)
            os.chown(dst, self.compile_uid, self.compile_gid)

        def _done_cb(task_id, stat):
            callback(stat['detect_error'])

        make_path = self.chal_path + '/compile'
        shutil.copytree(self.res_path + '/make', make_path, symlinks=True,
            copy_function=_copy_fn)
        os.chmod(make_path, mode=0o750)
        os.chown(make_path, self.compile_uid, self.compile_gid)
        shutil.copyfile(self.code_path, make_path + '/main.cpp',
            follow_symlinks=False)

        task_id = PyExt.create_task('/usr/bin/make',
            [],
            [
                'PATH=/usr/bin',
                'TMPDIR=/home/%d/compile'%self.uniqid,
                'OUT=./a.out',
            ],
            StdChal.null_fd, 1, 2,
            '/home/%d/compile'%self.uniqid, 'container/standard',
            self.compile_uid, self.compile_gid, 60000, 256 * 1024 * 1024,
            PyExt.RESTRICT_LEVEL_LOW)

        PyExt.start_task(task_id, _done_cb)

    @concurrent.return_future
    def judge_diff(self, in_path, ans_path, timelimit, memlimit, callback):
        infile_fd = os.open(in_path, os.O_RDONLY | os.O_CLOEXEC)
        ansfile = open(ans_path, 'rb')
        outpipe_fd = os.pipe2(os.O_CLOEXEC)
        result_stat = None
        result_pass = None

        def _started_cb(task_id):
            nonlocal infile_fd
            nonlocal outpipe_fd
            os.close(infile_fd)
            os.close(outpipe_fd[1])

        def _done_cb(task_id, stat):
            nonlocal result_stat
            nonlocal result_pass

            result_stat = (stat['utime'], stat['peakmem'], stat['detect_error'])
            if result_pass is not None:
                callback((result_pass, result_stat))

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
                        if len(ansfile.read(1)) == 0:
                            result_pass = True
                        else:
                            result_pass = False
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
        os.mkdir(judge_path, mode=0o751)
        shutil.copyfile(self.chal_path + '/compile/a.out',
            judge_path + '/a.out')
        os.chown(judge_path + '/a.out', judge_uid, judge_gid)
        os.chmod(judge_path + '/a.out', 0o100)

        IOLoop.instance().add_handler(outpipe_fd[0], _diff_out,
            IOLoop.READ | IOLoop.ERROR)

        task_id = PyExt.create_task('/home/%d/run_%d/a.out'%(
                self.uniqid, judge_uid),
            [],
            [],
            infile_fd, outpipe_fd[1], outpipe_fd[1],
            '/home/%d/run_%d'%(self.uniqid, judge_uid), 'container/standard',
            judge_uid, judge_gid, timelimit, memlimit,
            PyExt.RESTRICT_LEVEL_HIGH)

        PyExt.start_task(task_id, _done_cb, _started_cb)
