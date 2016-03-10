'''Standard challenge module.'''

import os
import shutil
import fcntl
from cffi import FFI
from tornado import gen, concurrent, process
from tornado.stack_context import StackContext
from tornado.ioloop import IOLoop
import PyExt
import Privilege
import Config
from Utils import FileUtils


STATUS_NONE = 0
STATUS_AC = 1
STATUS_WA = 2
STATUS_RE = 3
STATUS_TLE = 4
STATUS_MLE = 5
STATUS_CE = 6
STATUS_ERR = 7

MS_BIND = 4096


class StdChal:
    '''Standard challenge.

    Static attributes:
        last_uniqid (int): Last ID.
        last_standard_uid (int): Last UID for standard tasks.
        last_restrict_uid (int): Last UID for restricted tasks.
        null_fd (int): File descriptor of /dev/null.
        build_cache (dict): Cache information of builds.
        build_cache_refcount (dict): Refcount of build caches.

    Attributes:
        uniqid (int): Unique ID.
        code_path (string): Code path.
        res_path (string): Resource path.
        comp_typ (string): Type of compile.
        judge_typ (string): Type of judge.
        test_list ([dict]): Test parameter lists.
        metadata (dict): Metadata for judge.
        chal_id (int): Challenge ID.
        chal_path (string): Challenge path.

    '''

    last_uniqid = 0
    last_standard_uid = Config.CONTAINER_STANDARD_UID_BASE
    last_restrict_uid = Config.CONTAINER_RESTRICT_UID_BASE
    null_fd = None

    @staticmethod
    def init():
        '''Initialize the module.'''

        with StackContext(Privilege.fileaccess):
            try:
                shutil.rmtree('container/standard/home')
            except FileNotFoundError:
                pass
            os.mkdir('container/standard/home', mode=0o771)
            try:
                shutil.rmtree('container/standard/cache')
            except FileNotFoundError:
                pass
            os.mkdir('container/standard/cache', mode=0o771)

        ffi = FFI()
        ffi.cdef('''int mount(const char source[], const char target[],
            const char filesystemtype[], unsigned long mountflags,
            const void *data);''')
        ffi.cdef('''int umount(const char *target);''')
        libc = ffi.dlopen('libc.so.6')
        with StackContext(Privilege.fullaccess):
            libc.umount(b'container/standard/dev')
            libc.mount(b'/dev', b'container/standard/dev', b'', MS_BIND, \
                ffi.NULL)

        StdChal.null_fd = os.open('/dev/null', os.O_RDWR | os.O_CLOEXEC)
        StdChal.build_cache = {}
        StdChal.build_cache_refcount = {}

    @staticmethod
    def get_standard_ugid():
        '''Generate standard UID/GID.

        Returns:
            (int, int): Standard UID/GID

        '''

        StdChal.last_standard_uid += 1
        return (StdChal.last_standard_uid, StdChal.last_standard_uid)

    @staticmethod
    def get_restrict_ugid():
        '''Generate restrict UID/GID.

        Returns:
            (int, int): Restrict UID/GID

        '''

        StdChal.last_restrict_uid += 1
        return (StdChal.last_restrict_uid, StdChal.last_restrict_uid)

    @staticmethod
    def build_cache_find(res_path):
        '''Get build cache.

        Args:
            res_path (string): Resource path.

        Returns:
            (string, int): (cache hash, GID) or None if not found.

        '''

        try:
            return StdChal.build_cache[res_path]
        except KeyError:
            return None

    @staticmethod
    def build_cache_update(res_path, cache_hash, gid):
        '''Update build cache.

        Args:
            res_path (string): Resource path.
            cache_hash (int): Cache hash.
            gid (int): GID.

        Returns:
            None

        '''

        ret = StdChal.build_cache_find(res_path)
        if ret is not None:
            StdChal.build_cache_decref(ret[0])
            del StdChal.build_cache[res_path]

        StdChal.build_cache[res_path] = (cache_hash, gid)
        StdChal.build_cache_refcount[cache_hash] = 1

    @staticmethod
    def build_cache_incref(cache_hash):
        '''Increment the refcount of the build cache.

        Args:
            cache_hash (int): Cache hash.

        Returns:
            None

        '''

        StdChal.build_cache_refcount[cache_hash] += 1

    @staticmethod
    def build_cache_decref(cache_hash):
        '''Decrement the refcount of the build cache.

        Delete the build cache if the refcount = 0.

        Args:
            cache_hash (int): Cache hash.

        Returns:
            None

        '''

        StdChal.build_cache_refcount[cache_hash] -= 1
        if StdChal.build_cache_refcount[cache_hash] == 0:
            with StackContext(Privilege.fileaccess):
                shutil.rmtree('container/standard/cache/%x'%cache_hash)

    def __init__(self, chal_id, code_path, comp_typ, judge_typ, res_path, \
        test_list, metadata):
        '''Initialize.

        Args:
            chal_id (int): Challenge ID.
            code_path (string): Code path.
            comp_typ (string): Type of compile.
            judge_typ (string): Type of judge.
            res_path (string): Resource path.
            test_list ([dict]): Test parameter lists.
            metadata (dict): Metadata for judge.

        '''

        StdChal.last_uniqid += 1
        self.uniqid = StdChal.last_uniqid
        self.code_path = code_path
        self.res_path = res_path
        self.comp_typ = comp_typ
        self.judge_typ = judge_typ
        self.test_list = test_list
        self.metadata = metadata
        self.chal_id = chal_id
        self.chal_path = None

        StdChal.last_standard_uid += 1
        self.compile_uid, self.compile_gid = StdChal.get_standard_ugid()

    @gen.coroutine
    def prefetch(self):
        '''Prefetch files.'''

        path_set = set([self.code_path])
        for test in self.test_list:
            path_set.add(os.path.abspath(test['ans']))
        for root, _, files in os.walk(self.res_path):
            for filename in files:
                path_set.add(os.path.abspath(os.path.join(root, filename)))

        path_list = list(path_set)
        proc_list = []

        with StackContext(Privilege.fileaccess):
            for idx in range(0, len(path_list), 16):
                proc_list.append(process.Subprocess(
                    ['./Prefetch.py'] + path_list[idx:idx + 16],
                    stdout=process.Subprocess.STREAM))

        for proc in proc_list:
            yield proc.stdout.read_bytes(2)

    @gen.coroutine
    def start(self):
        '''Start the challenge.

        Returns:
            dict: Challenge result.

        '''

        cache_hash = None
        cache_gid = None
        # Check if special judge needs to rebuild.
        if self.judge_typ in ['ioredir']:
            hashproc = process.Subprocess( \
                ['./HashDir.py', self.res_path + '/check'], \
                stdout=process.Subprocess.STREAM)
            dirhash = yield hashproc.stdout.read_until(b'\n')
            dirhash = int(dirhash.decode('utf-8').rstrip('\n'), 16)

            ret = StdChal.build_cache_find(self.res_path)
            if ret is not None and ret[0] == dirhash:
                cache_hash, cache_gid = ret
                judge_ioredir = IORedirJudge('container/standard', \
                    '/cache/%x'%cache_hash)

            else:
                cache_hash = dirhash
                _, cache_gid = StdChal.get_standard_ugid()
                build_ugid = StdChal.get_standard_ugid()
                build_relpath = '/cache/%x'%cache_hash
                build_path = 'container/standard' + build_relpath

                judge_ioredir = IORedirJudge('container/standard', \
                    build_relpath)
                if not (yield judge_ioredir.build(build_ugid, self.res_path)):
                    return [(0, 0, STATUS_ERR)] * len(self.test_list)
                FileUtils.setperm(build_path, \
                    Privilege.JUDGE_UID, cache_gid, umask=0o750)
                with StackContext(Privilege.fullaccess):
                    os.chmod(build_path, 0o750)

                StdChal.build_cache_update(self.res_path, cache_hash, cache_gid)
                print('StdChal %d built checker %x'%(self.chal_id, cache_hash))

            StdChal.build_cache_incref(cache_hash)

        print('StdChal %d started'%self.chal_id)

        # Create challenge environment.
        self.chal_path = 'container/standard/home/%d'%self.uniqid
        with StackContext(Privilege.fileaccess):
            os.mkdir(self.chal_path, mode=0o771)

        try:
            yield self.prefetch()
            print('StdChal %d prefetched'%self.chal_id)

            if self.comp_typ in ['g++', 'clang++']:
                ret = yield self.comp_cxx()

            elif self.comp_typ == 'makefile':
                ret = yield self.comp_make()

            elif self.comp_typ == 'python3':
                ret = yield self.comp_python()

            if ret != PyExt.DETECT_NONE:
                return [(0, 0, STATUS_CE)] * len(self.test_list)
            print('StdChal %d compiled'%self.chal_id)

            # Prepare test arguments
            if self.comp_typ == 'python3':
                exefile_path = self.chal_path \
                    + '/compile/__pycache__/test.cpython-34.pyc'
                exe_path = '/usr/bin/python3.4'
                argv = ['./a.out']
                envp = ['HOME=/', 'LANG=en_US.UTF-8']

            else:
                exefile_path = self.chal_path + '/compile/a.out'
                exe_path = './a.out'
                argv = []
                envp = []

            # Prepare judge
            test_future = []
            if self.judge_typ == 'diff':
                for test in self.test_list:
                    test_future.append(self.judge_diff(
                        exefile_path,
                        exe_path, argv, envp,
                        test['in'], test['ans'],
                        test['timelimit'], test['memlimit']))
            elif self.judge_typ == 'ioredir':
                for test in self.test_list:
                    check_uid, _ = StdChal.get_standard_ugid()
                    test_uid, test_gid = StdChal.get_restrict_ugid()
                    test_future.append(judge_ioredir.judge( \
                        exefile_path, exe_path, argv, envp, \
                        (check_uid, cache_gid), \
                        (test_uid, test_gid), \
                        '/home/%d/run_%d'%(self.uniqid, test_uid), \
                        test, self.metadata))

            # Emit tests
            test_result = yield gen.multi(test_future)
            ret_result = list()
            for result in test_result:
                test_pass, data = result
                runtime, peakmem, error = data
                status = STATUS_ERR
                if error == PyExt.DETECT_NONE:
                    if test_pass is True:
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

            return ret_result

        finally:
            if cache_hash is not None:
                StdChal.build_cache_decref(cache_hash)
            with StackContext(Privilege.fileaccess):
                shutil.rmtree(self.chal_path)
            print('StdChal %d done'%self.chal_id)

    @concurrent.return_future
    def comp_cxx(self, callback=None):
        '''GCC, Clang compile.

        Args:
            callback (function): Callback of return_future.

        Returns:
            None

        '''

        def _done_cb(task_id, stat):
            '''Done callback.

            Args:
                task_id (int): Task ID.
                stat (dict): Task result.

            Returns:
                None

            '''

            callback(stat['detect_error'])

        compile_path = self.chal_path + '/compile'
        with StackContext(Privilege.fileaccess):
            os.mkdir(compile_path, mode=0o770)
            shutil.copyfile(self.code_path, compile_path + '/test.cpp', \
                follow_symlinks=False)
        FileUtils.setperm(compile_path, self.compile_uid, self.compile_gid)

        if self.comp_typ == 'g++':
            compiler = '/usr/bin/g++'
        elif self.comp_typ == 'clang++':
            compiler = '/usr/bin/clang++'

        task_id = PyExt.create_task(compiler, \
            [
                '-O2',
                '-std=c++14',
                '-o', './a.out',
                './test.cpp',
            ], \
            [
                'PATH=/usr/bin:/bin',
                'TMPDIR=/home/%d/compile'%self.uniqid,
            ], \
            {
                0: StdChal.null_fd,
                1: StdChal.null_fd,
                2: StdChal.null_fd,
            }, \
            '/home/%d/compile'%self.uniqid, 'container/standard', \
            self.compile_uid, self.compile_gid, 60000, 1024 * 1024 * 1024, \
            PyExt.RESTRICT_LEVEL_LOW)

        if task_id is None:
            callback(PyExt.DETECT_INTERNALERR)
        else:
            PyExt.start_task(task_id, _done_cb)

    @concurrent.return_future
    def comp_make(self, callback=None):
        '''Makefile compile.

        Args:
            callback (function): Callback of return_future.

        Returns:
            None

        '''

        def _done_cb(task_id, stat):
            '''Done callback.

            Args:
                task_id (int): Task ID.
                stat (dict): Task result.

            Returns:
                None

            '''

            callback(stat['detect_error'])

        make_path = self.chal_path + '/compile'
        FileUtils.copydir(self.res_path + '/make', make_path)
        with StackContext(Privilege.fileaccess):
            shutil.copyfile(self.code_path, make_path + '/main.cpp', \
                follow_symlinks=False)
        FileUtils.setperm(make_path, self.compile_uid, self.compile_gid)
        with StackContext(Privilege.fullaccess):
            os.chmod(make_path, mode=0o770)

        task_id = PyExt.create_task('/usr/bin/make', \
            [], \
            [
                'PATH=/usr/bin:/bin',
                'TMPDIR=/home/%d/compile'%self.uniqid,
                'OUT=./a.out',
            ], \
            {
                0: StdChal.null_fd,
                1: StdChal.null_fd,
                2: StdChal.null_fd,
            }, \
            '/home/%d/compile'%self.uniqid, 'container/standard', \
            self.compile_uid, self.compile_gid, 60000, 1024 * 1024 * 1024, \
            PyExt.RESTRICT_LEVEL_LOW)

        if task_id is None:
            callback(PyExt.DETECT_INTERNALERR)
        else:
            PyExt.start_task(task_id, _done_cb)

    @concurrent.return_future
    def comp_python(self, callback=None):
        '''Python3.4 compile.

        Args:
            callback (function): Callback of return_future.

        Returns:
            None

        '''

        def _done_cb(task_id, stat):
            '''Done callback.

            Args:
                task_id (int): Task ID.
                stat (dict): Task result.

            Returns:
                None

            '''

            callback(stat['detect_error'])

        compile_path = self.chal_path + '/compile'
        with StackContext(Privilege.fileaccess):
            os.mkdir(compile_path, mode=0o770)
            shutil.copyfile(self.code_path, compile_path + '/test.py', \
                follow_symlinks=False)
        FileUtils.setperm(compile_path, self.compile_uid, self.compile_gid)

        task_id = PyExt.create_task('/usr/bin/python3.4', \
            [
                '-m',
                'py_compile',
                './test.py'
            ], \
            [
                'HOME=/home/%d/compile'%self.uniqid,
                'LANG=en_US.UTF-8'
            ], \
            {
                0: StdChal.null_fd,
                1: StdChal.null_fd,
                2: StdChal.null_fd,
            }, \
            '/home/%d/compile'%self.uniqid, 'container/standard', \
            self.compile_uid, self.compile_gid, 60000, 1024 * 1024 * 1024, \
            PyExt.RESTRICT_LEVEL_LOW)

        if task_id is None:
            callback(PyExt.DETECT_INTERNALERR)
        else:
            PyExt.start_task(task_id, _done_cb)

    @concurrent.return_future
    def judge_diff(self, src_path, exe_path, argv, envp, in_path, ans_path, \
        timelimit, memlimit, callback=None):
        '''Diff judge.

        Args:
            src_path (string): Executable source path.
            exe_path (string): Executable or interpreter path in the sandbox.
            argv ([string]): List of arguments.
            envp ([string]): List of environment variables.
            in_path (string): Input file path.
            ans_path (string): Answer file path.
            timelimit (int): Timelimit.
            memlimit (int): Memlimit.
            callback (function): Callback of return_future.

        Returns:
            None

        '''

        def _started_cb(task_id):
            '''Started callback.

            Close unused file descriptor after the task is started.

            Args:
                task_id (int): Task ID.

            Returns:
                None

            '''

            nonlocal infile_fd
            nonlocal outpipe_fd

            os.close(infile_fd)
            os.close(outpipe_fd[1])
            IOLoop.instance().add_handler(outpipe_fd[0], _diff_out, \
                IOLoop.READ | IOLoop.ERROR)

        def _done_cb(task_id, stat):
            '''Done callback.

            Args:
                task_id (int): Task ID.
                stat (dict): Task result.

            Returns:
                None

            '''

            nonlocal result_stat
            nonlocal result_pass

            result_stat = (stat['utime'], stat['peakmem'], stat['detect_error'])
            if result_pass is not None:
                callback((result_pass, result_stat))

        def _diff_out(evfd, events):
            '''Diff the output of the task.

            Args:
                evfd (int): Event file descriptor.
                events (int): Event flags.

            Returns:
                None

            '''

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
                if result_pass is None:
                    if len(ansfile.read(1)) == 0:
                        result_pass = True
                    else:
                        result_pass = False

                IOLoop.instance().remove_handler(evfd)
                os.close(outpipe_fd[0])
                ansfile.close()

                if result_stat is not None:
                    callback((result_pass, result_stat))

        judge_uid, judge_gid = StdChal.get_restrict_ugid()

        # Prepare I/O and stat.
        with StackContext(Privilege.fileaccess):
            infile_fd = os.open(in_path, os.O_RDONLY | os.O_CLOEXEC)
            ansfile = open(ans_path, 'rb')
        outpipe_fd = os.pipe2(os.O_CLOEXEC)
        fcntl.fcntl(outpipe_fd[0], fcntl.F_SETFL, os.O_NONBLOCK)
        result_stat = None
        result_pass = None

        # Prepare judge environment.
        with StackContext(Privilege.fileaccess):
            judge_path = self.chal_path + '/run_%d'%judge_uid
            os.mkdir(judge_path, mode=0o771)
            shutil.copyfile(src_path, judge_path + '/a.out', \
                follow_symlinks=False)
        with StackContext(Privilege.fullaccess):
            os.chown(judge_path + '/a.out', judge_uid, judge_gid)
            os.chmod(judge_path + '/a.out', 0o500)

        task_id = PyExt.create_task(exe_path, argv, envp, \
            {
                0: infile_fd,
                1: outpipe_fd[1],
                2: outpipe_fd[1],
            }, \
            '/home/%d/run_%d'%(self.uniqid, judge_uid), 'container/standard', \
            judge_uid, judge_gid, timelimit, memlimit, \
            PyExt.RESTRICT_LEVEL_HIGH)

        if task_id is None:
            os.close(infile_fd)
            os.close(outpipe_fd[0])
            os.close(outpipe_fd[1])
            ansfile.close()
            callback((False, (0, 0, PyExt.DETECT_INTERNALERR)))
        else:
            PyExt.start_task(task_id, _done_cb, _started_cb)


class IORedirJudge:
    '''I/O redirect spcial judge.

    Attributes:
        container_path (string): Container path.
        build_relpath (string): Relative build path.
        build_path (string): Build path.

    '''

    def __init__(self, container_path, build_relpath):
        '''Initialize.

        Args:
            container_path (string): Container path.
            build_relpath (string): Relative build path.

        '''

        self.container_path = container_path
        self.build_relpath = build_relpath
        self.build_path = container_path + build_relpath

    @concurrent.return_future
    def build(self, build_ugid, res_path, callback=None):
        '''Build environment.

        Args:
            build_ugid ((int, int)): Build UID/GID.
            res_path (string): Resource path.
            callback (function): Callback of return_future.

        Returns:
            None

        '''

        def _done_cb(task_id, stat):
            '''Done callback.

            Args:
                task_id (int): Task ID.
                stat (dict): Task result.

            Returns:
                None

            '''

            if stat['detect_error'] == PyExt.DETECT_NONE:
                callback(True)
            else:
                callback(False)

        build_uid, build_gid = build_ugid

        # Prepare build environment.
        FileUtils.copydir(res_path + '/check', self.build_path)
        FileUtils.setperm(self.build_path, build_uid, build_gid)
        with StackContext(Privilege.fullaccess):
            os.chmod(self.build_path, mode=0o770)

        with StackContext(Privilege.fileaccess):
            if not os.path.isfile(self.build_path + '/build'):
                callback(True)
                return

        # Build.
        task_id = PyExt.create_task(self.build_relpath + '/build', \
            [], \
            [
                'PATH=/usr/bin:/bin',
                'TMPDIR=%s'%self.build_relpath,
                'HOME=%s'%self.build_relpath,
                'LANG=en_US.UTF-8'
            ], \
            {
                0: 0,
                1: 1,
                2: 2,
            }, \
            self.build_relpath, 'container/standard', \
            build_uid, build_gid, 60000, 1024 * 1024 * 1024, \
            PyExt.RESTRICT_LEVEL_LOW)

        if task_id is None:
            callback(False)
        else:
            PyExt.start_task(task_id, _done_cb)

    @concurrent.return_future
    def judge(self, src_path, exe_relpath, argv, envp, check_ugid, test_ugid, \
        test_relpath, test_param, metadata, callback=None):
        '''I/O redirect special judge.

        Args:
            src_path (string): Executable source path.
            exe_relpath (string): Executable or interpreter path in the sandbox.
            argv ([string]): List of arguments.
            envp ([string]): List of environment variables.
            check_ugid (int, int): Check UID/GID.
            test_ugid (int, int): Test UID/GID.
            test_relpath (string): Test relative path.
            test_param (dict): Test parameters.
            metadata (dict): Metadata.
            callback (function): Callback of return_future.

        Returns:
            None

        '''

        def _check_started_cb(task_id):
            '''Check started callback.

            Close unused file descriptor after the check is started.

            Args:
                task_id (int): Task ID.

            Returns:
                None

            '''

            nonlocal inpipe_fd
            nonlocal outpipe_fd
            nonlocal ansfile_fd
            nonlocal check_infile_fd

            os.close(inpipe_fd[1])
            os.close(outpipe_fd[0])
            if ansfile_fd is not None:
                os.close(ansfile_fd)
            if check_infile_fd is not None:
                os.close(check_infile_fd)

        def _test_started_cb(task_id):
            '''Test started callback.

            Close unused file descriptor after the test is started.

            Args:
                task_id (int): Task ID.

            Returns:
                None

            '''

            nonlocal inpipe_fd
            nonlocal outpipe_fd
            nonlocal outfile_fd
            nonlocal test_infile_fd

            os.close(inpipe_fd[0])
            os.close(outpipe_fd[1])
            os.close(outfile_fd)
            if test_infile_fd is not None:
                os.close(test_infile_fd)

        def _done_cb():
            '''Done callback.'''

            nonlocal result_stat
            nonlocal result_pass

            if result_pass is not None and result_stat is not None:
                callback((result_pass, result_stat))
                return

        def _check_done_cb(task_id, stat):
            '''Check done callback.

            Args:
                task_id (int): Task ID.
                stat (dict): Task result.

            Returns:
                None

            '''

            nonlocal result_pass

            if stat['detect_error'] == PyExt.DETECT_NONE:
                result_pass = True
            else:
                result_pass = False
            _done_cb()

        def _test_done_cb(task_id, stat):
            '''Test done callback.

            Args:
                task_id (int): Task ID.
                stat (dict): Task result.

            Returns:
                None

            '''

            nonlocal result_stat

            result_stat = (stat['utime'], stat['peakmem'], stat['detect_error'])
            _done_cb()

        result_stat = None
        result_pass = None
        in_path = test_param['in']
        ans_path = test_param['ans']
        timelimit = test_param['timelimit']
        memlimit = test_param['memlimit']
        check_uid, check_gid = check_ugid
        test_uid, test_gid = test_ugid

        test_path = self.container_path + test_relpath
        output_relpath = test_relpath + '/output.txt'
        output_path = self.container_path + output_relpath
        verdict_relpath = test_relpath + '/verdict.txt'
        verdict_path = self.container_path + verdict_relpath

        # Prepare test environment.
        with StackContext(Privilege.fileaccess):
            os.mkdir(test_path, mode=0o771)
            shutil.copyfile(src_path, test_path + '/a.out', \
                follow_symlinks=False)
        with StackContext(Privilege.fullaccess):
            os.chown(test_path + '/a.out', test_uid, test_gid)
            os.chmod(test_path + '/a.out', 0o500)

        # Prepare I/O.
        with StackContext(Privilege.fileaccess):
            try:
                check_infile_fd = os.open(in_path, os.O_RDONLY | os.O_CLOEXEC)
                test_infile_fd = os.open(in_path, os.O_RDONLY | os.O_CLOEXEC)
            except FileNotFoundError:
                check_infile_fd = None
                test_infile_fd = None
            try:
                ansfile_fd = os.open(ans_path, os.O_RDONLY | os.O_CLOEXEC)
            except FileNotFoundError:
                ansfile_fd = None
            outfile_fd = os.open(output_path, \
                os.O_WRONLY | os.O_CREAT | os.O_CLOEXEC, mode=0o400)
            os.close(os.open(verdict_path, \
                os.O_WRONLY | os.O_CREAT | os.O_CLOEXEC, mode=0o400))
        with StackContext(Privilege.fullaccess):
            os.chown(output_path, check_uid, check_gid)
            os.chown(verdict_path, check_uid, check_gid)

        inpipe_fd = os.pipe2(os.O_CLOEXEC)
        outpipe_fd = os.pipe2(os.O_CLOEXEC)

        # Set file descriptor mapping.
        check_fdmap = {
            0: StdChal.null_fd,
            1: StdChal.null_fd,
            2: StdChal.null_fd,
        }
        test_fdmap = {
            0: StdChal.null_fd,
            1: StdChal.null_fd,
            2: StdChal.null_fd,
        }
        if check_infile_fd is not None:
            check_fdmap[metadata['redir_check']['testin']] = check_infile_fd
        if ansfile_fd is not None:
            check_fdmap[metadata['redir_check']['ansin']] = ansfile_fd
        check_fdmap[metadata['redir_check']['pipein']] = inpipe_fd[1]
        check_fdmap[metadata['redir_check']['pipeout']] = outpipe_fd[0]
        try:
            del check_fdmap[-1]
        except KeyError:
            pass
        if test_infile_fd is not None:
            test_fdmap[metadata['redir_test']['testin']] = test_infile_fd
        test_fdmap[metadata['redir_test']['testout']] = outfile_fd
        test_fdmap[metadata['redir_test']['pipein']] = inpipe_fd[0]
        test_fdmap[metadata['redir_test']['pipeout']] = outpipe_fd[1]
        try:
            del test_fdmap[-1]
        except KeyError:
            pass

        check_task_id = PyExt.create_task(self.build_relpath + '/check', \
            [], \
            [
                'PATH=/usr/bin:/bin',
                'HOME=%s'%self.build_relpath,
                'LANG=en_US.UTF-8',
                'OUTPUT=%s'%output_relpath,
                'VERDICT=%s'%verdict_relpath,
            ], \
            check_fdmap, \
            self.build_relpath, self.container_path, \
            check_uid, check_gid, 60000, 1024 * 1024 * 1024, \
            PyExt.RESTRICT_LEVEL_LOW)

        if check_task_id is None:
            callback((False, (0, 0, PyExt.DETECT_INTERNALERR)))
            return
        PyExt.start_task(check_task_id, _check_done_cb, _check_started_cb)

        test_task_id = PyExt.create_task(exe_relpath, argv, envp, \
            test_fdmap, \
            test_relpath, self.container_path, \
            test_uid, test_gid, timelimit, memlimit, \
            PyExt.RESTRICT_LEVEL_HIGH)

        if test_task_id is None:
            callback((False, (0, 0, PyExt.DETECT_INTERNALERR)))
            return
        PyExt.start_task(test_task_id, _test_done_cb, _test_started_cb)
