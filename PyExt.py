from cffi import FFI
from collections import deque
from tornado.ioloop import IOLoop
import Config


RESTRICT_LEVEL_LOW = 0
RESTRICT_LEVEL_HIGH = 1

DETECT_NONE = 0
DETECT_OOM = 1
DETECT_TIMEOUT = 2
DETECT_FORCETIMEOUT = 3
DETECT_EXITERR = 4
DETECT_INTERNALERR = 5

ffi = None
pyextlib = None
task_stop_cb = None
task_map = {}
task_queue = deque()
task_running_count = 0


class UvPoll:
    def __init__(self):
        global ffi
        global pyextlib

        self.ffi = ffi
        self.pyextlib = pyextlib
        self.pollpairs = self.ffi.new('pollpair[]', 65536)

    def close(self):
        raise NotImplemented()

    def register(self, fd, events):
        self.pyextlib.ext_register(fd, events)

    def unregister(self, fd):
        self.pyextlib.ext_unregister(fd)

    def modify(self, fd, events):
        self.pyextlib.ext_modify(fd, events)

    def poll(self, timeout, maxevts = 65536):
        assert(maxevts <= 65536)

        num = self.pyextlib.ext_poll(self.pollpairs, int(timeout * 1000))
        pairs = list()
        for idx in range(num):
            pairs.append((
                int(self.pollpairs[idx].fd),
                int(self.pollpairs[idx].events)
            ))

        return pairs


def init():
    global ffi
    global pyextlib
    global task_stop_cb
    global evt_pollpairs

    ffi = FFI()
    ffi.cdef('''
        typedef struct {
            int fd;
            uint32_t events;
        } pollpair;
    ''')
    ffi.cdef('''
        struct taskstat {
            unsigned long utime;
            unsigned long stime;
            unsigned long peakmem;
            int detect_error;
        };
    ''')
    ffi.cdef('''int init();''')
    ffi.cdef('''int ext_register(int fd, int events);''')
    ffi.cdef('''int ext_unregister(int fd);''')
    ffi.cdef('''int ext_modify(int fd, int events);''')
    ffi.cdef('''int ext_poll(pollpair[], int timeout);''')
    ffi.cdef('''unsigned long create_task(
        char exe_path[], char *argv[], char *envp[], 
        int stdin_fd, int stdout_fd, int stderr_fd, 
        char work_path[], char root_path[], 
        unsigned int uid, unsigned int gid, 
        unsigned long timelimit, unsigned long memlimit, 
        int restrict_level);''')
    ffi.cdef('''int start_task(unsigned long id,
        void (*callback)(unsigned long id, struct taskstat stat));''')

    pyextlib = ffi.dlopen('lib/libpyext.so')
    pyextlib.init()

    @ffi.callback('void(unsigned long, struct taskstat)')
    def task_stop_cb(task_id, stat):
        global task_map
        global task_running_count

        callback, _ = task_map[task_id]
        del task_map[task_id]

        IOLoop.instance().add_callback(
            callback,
            task_id,
            {
                'utime': int(stat.utime),
                'stime': int(stat.stime),
                'peakmem': int(stat.peakmem),
                'detect_error': int(stat.detect_error),
            }
        )

        task_running_count -= 1
        IOLoop.instance().add_callback(emit_task)


def create_task(
    exe_path,
    argv,
    envp,
    stdin_fd,
    stdout_fd,
    stderr_fd,
    work_path,
    root_path,
    uid,
    gid,
    timelimit,
    memlimit,
    restrict_level
):
    global ffi
    global pyextlib

    ffi_argv = []
    for arg in argv:
        ffi_argv.append(ffi.new('char[]', arg.encode('utf-8')))
    ffi_argv.append(ffi.NULL)

    ffi_envp = []
    for env in envp:
        ffi_envp.append(ffi.new('char[]', env.encode('utf-8')))
    ffi_envp.append(ffi.NULL)

    task_id = pyextlib.create_task(
        ffi.new('char[]', exe_path.encode('utf-8')),
        ffi_argv, ffi_envp,
        stdin_fd, stdout_fd, stderr_fd,
        ffi.new('char[]', work_path.encode('utf-8')),
        ffi.new('char[]', root_path.encode('utf-8')),
        uid, gid, timelimit, memlimit, restrict_level)

    if task_id == 0:
        return None

    return task_id


def start_task(task_id, callback, started_callback=None):
    global task_stop_cb
    global task_map
    global task_queue

    task_map[task_id] = (callback, started_callback)
    task_queue.append(task_id)
    emit_task()


def emit_task():
    global task_map
    global task_queue
    global task_running_count

    while len(task_queue) > 0 \
        and task_running_count < Config.TASK_MAXCONCURRENT:
        task_id = task_queue.popleft()
        task_running_count += 1
        callback, started_callback = task_map[task_id]

        pyextlib.start_task(task_id, task_stop_cb)

        if started_callback is not None:
            started_callback(task_id)
