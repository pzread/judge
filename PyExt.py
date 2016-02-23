'''C extension interface.

Attributes:
    FFI (ffi): cffi interface.
    FFILIB (object): cffi library.

'''

from collections import deque
import cffi
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

FFI = None
FFILIB = None
TASK_MAP = None
TASK_QUEUE = None
TASK_RUNNING_COUNT = 0
TASK_STOP_CB = None


class EvPoll:
    '''Evpoll interface.

    Attributes:
        ffi (ffi): cffi interface.
        ffilib (object): cffi library.
        pollpairs (object): cffi polling pair buffer.

    '''

    def __init__(self):
        '''Initialize.'''

        self.ffi = FFI
        self.ffilib = FFILIB
        self.pollpairs = self.ffi.new('pollpair[]', 65536)

    def close(self):
        '''Handle close.'''

        self.ffilib.destroy()

    def register(self, evfd, events):
        '''Register event.

        Args:
            evfd (int): File descriptor.
            events (int): Event flag.

        Returns:
            None

        '''

        self.ffilib.ext_register(evfd, events)

    def unregister(self, evfd):
        '''Unregister event.

        Args:
            evfd (int): File descriptor.

        Returns:
            None

        '''

        self.ffilib.ext_unregister(evfd)

    def modify(self, evfd, events):
        '''Modify event flag.

        Args:
            evfd (int): File descriptor.
            events (int): Event flag.

        Returns:
            None

        '''

        self.ffilib.ext_modify(evfd, events)

    def poll(self, timeout, maxevts=65536):
        '''Poll events.

        Args:
            timeout (int): Timeout.
            maxevts (int): Maximum number of events which are polled.

        Returns:
            [(int, int)]: Event pairs (fd, events).

        '''

        assert maxevts <= 65536

        num = self.ffilib.ext_poll(self.pollpairs, int(timeout * 1000))
        pairs = list()
        for idx in range(num):
            pairs.append((
                int(self.pollpairs[idx].fd),
                int(self.pollpairs[idx].events)
            ))

        return pairs


def init():
    '''Initialize the module.'''

    global FFI
    global FFILIB
    global TASK_MAP
    global TASK_QUEUE
    global TASK_STOP_CB

    TASK_MAP = {}
    TASK_QUEUE = deque()

    FFI = cffi.FFI()
    FFI.cdef('''
        typedef struct {
            int fd;
            uint32_t events;
        } pollpair;
    ''')
    FFI.cdef('''
        struct taskstat {
            uint64_t utime;
            uint64_t stime;
            uint64_t peakmem;
            int detect_error;
        };
    ''')
    FFI.cdef('''int init();''')
    FFI.cdef('''void destroy();''')
    FFI.cdef('''int ext_register(int fd, int events);''')
    FFI.cdef('''int ext_unregister(int fd);''')
    FFI.cdef('''int ext_modify(int fd, int events);''')
    FFI.cdef('''int ext_poll(pollpair[], int timeout);''')
    FFI.cdef('''uint64_t create_task(
        char exe_path[], char *argv[], char *envp[], 
        int stdin_fd, int stdout_fd, int stderr_fd, 
        char work_path[], char root_path[], 
        unsigned int uid, unsigned int gid, 
        uint64_t timelimit, uint64_t memlimit, 
        int restrict_level);''')
    FFI.cdef('''int start_task(uint64_t id,
        void (*callback)(uint64_t id, struct taskstat stat));''')

    FFILIB = FFI.dlopen('lib/libpyext.so')
    FFILIB.init()

    @FFI.callback('void(uint64_t, struct taskstat)')
    def task_stop_cb(task_id, stat):
        '''Task stop callback of cffi.

        Args:
            task_id (int): Task ID.
            stat (object): Task result.

        Returns:
            None

        '''

        global TASK_RUNNING_COUNT

        callback, _ = TASK_MAP[task_id]
        del TASK_MAP[task_id]

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

        TASK_RUNNING_COUNT -= 1
        IOLoop.instance().add_callback(emit_task)

    TASK_STOP_CB = task_stop_cb


def create_task(exe_path, argv, envp, stdin_fd, stdout_fd, stderr_fd, \
    work_path, root_path, uid, gid, timelimit, memlimit, restrict_level):
    '''Create a task.

    Args:
        exe_path (string): Executable file path.
        argv ([string]): List of arguments.
        envp ([string]): List of environment variables.
        stdin_fd (int): Standard input file descriptor.
        stdout_fd (int): Standard output file descriptor.
        stderr_fd (int): Standard error file descriptor.
        work_path (string): Working directory.
        root_path (string): Root directory.
        uid (int): UID of sandbox.
        gid (int): GID of sandbox.
        timelimit (int): Timelimit of sandbox.
        memlimit (int): Memlimit of sandbox.
        restrict_level (int): Restriction level of sandbox.

    Returns:
        int: Task ID, or None if failed to create the task.

    '''

    ffi_argv = []
    for arg in argv:
        ffi_argv.append(FFI.new('char[]', arg.encode('utf-8')))
    ffi_argv.append(FFI.NULL)

    ffi_envp = []
    for env in envp:
        ffi_envp.append(FFI.new('char[]', env.encode('utf-8')))
    ffi_envp.append(FFI.NULL)

    task_id = FFILIB.create_task(
        FFI.new('char[]', exe_path.encode('utf-8')),
        ffi_argv, ffi_envp,
        stdin_fd, stdout_fd, stderr_fd,
        FFI.new('char[]', work_path.encode('utf-8')),
        FFI.new('char[]', root_path.encode('utf-8')),
        uid, gid, timelimit, memlimit, restrict_level)

    if task_id == 0:
        return None

    return task_id


def start_task(task_id, callback, started_callback=None):
    '''Start a task.

    The task may be pended if the running queue is full.

    Args:
        task_id (int): Task ID.
        callback (function): Done callback.
        started_callback (function, optinal): Started callback.

    Returns:
        None

    '''

    TASK_MAP[task_id] = (callback, started_callback)
    TASK_QUEUE.append(task_id)
    emit_task()


def emit_task():
    '''Emit tasks.'''

    global TASK_RUNNING_COUNT

    while len(TASK_QUEUE) > 0 \
        and TASK_RUNNING_COUNT < Config.TASK_MAXCONCURRENT:
        task_id = TASK_QUEUE.popleft()
        TASK_RUNNING_COUNT += 1
        _, started_callback = TASK_MAP[task_id]

        FFILIB.start_task(task_id, TASK_STOP_CB)

        if started_callback is not None:
            started_callback(task_id)
