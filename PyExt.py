from cffi import FFI
from tornado.ioloop import IOLoop


ffi = None
pyextlib = None
task_callback = {}


class UvPoll:
    UV_READABLE = 1
    UV_WRITEABLE = 2

    def __init__(self):
        global ffi
        global pyextlib

        self.ffi = ffi
        self.pyextlib = pyextlib

    def close(self):
        raise NotImplemented()

    def evt_to_uvevt(self, events):
        uv_events = 0
        if (events & IOLoop.READ) == IOLoop.READ:
            uv_events |= UvPoll.UV_READABLE
        if (events & IOLoop.WRITE) == IOLoop.WRITE:
            uv_events |= UvPoll.UV_WRITEABLE
        return uv_events

    def register(self, fd, events):
        self.pyextlib.ev_register(fd, self.evt_to_uvevt(events))

    def unregister(self, fd):
        self.pyextlib.ev_unregister(fd)

    def modify(self, fd, events):
        self.pyextlib.ev_modify(fd, self.evt_to_uvevt(events))

    def poll(self, timeout, maxevts = 256):
        evts = self.ffi.new('eventpair[]', maxevts)
        num = self.pyextlib.ev_poll(int(timeout * 1000), evts, maxevts)
        pairs = list()
        for idx in range(num):
            evt = evts[idx]
            if evt.events < 0:
                events = IOLoop.ERROR
            else:
                events = 0
                if evt.events & UvPoll.UV_READABLE:
                    events |= IOLoop.READ
                if evt.events & UvPoll.UV_WRITEABLE:
                    events |= IOLoop.WRITE
            pairs.append((evt.fd, events))

        return pairs


def init():
    global ffi
    global pyextlib

    ffi = FFI()
    ffi.cdef('''
        typedef struct {
            int fd;
            int events;
        } eventpair;
    ''')
    ffi.cdef('''int init();''')
    ffi.cdef('''int ev_register(int fd, int events);''')
    ffi.cdef('''int ev_unregister(int fd);''')
    ffi.cdef('''int ev_modify(int fd, int events);''')
    ffi.cdef('''int ev_poll(long timeout, eventpair ret[], int maxevts);''')
    ffi.cdef('''unsigned long create_task(
        char exe_path[], char *argv[], char *envp[],
        char work_path[], char root_path[],
        unsigned int uid, unsigned int gid,
        unsigned long timelimit, unsigned long memlimit);''')
    ffi.cdef('''int start_task(
        unsigned long id,
        void (*callback)(unsigned long id));''')
    pyextlib = ffi.dlopen('lib/libpyext.so')
    pyextlib.init()

    global done_cb
    @ffi.callback('void(unsigned long)')
    def done_cb(task_id):
        global task_callback
        task_callback[task_id](task_id)


def create_task(
    exe_path,
    argv,
    envp,
    work_path,
    root_path,
    uid,
    gid,
    timelimit,
    memlimit
):
    global ffi
    global pyextlib

    ffi_exe_path = ffi.new('char[]', exe_path.encode('utf-8'))
    ffi_argv = []
    for arg in argv:
        ffi_argv.append(ffi.new('char[]', arg.encode('utf-8')))
    ffi_argv.append(ffi.NULL)
    ffi_envp = []
    for env in envp:
        ffi_envp.append(ffi.new('char[]', env.encode('utf-8')))
    ffi_envp.append(ffi.NULL)
    ffi_work_path = ffi.new('char[]', work_path.encode('utf-8'))
    ffi_root_path = ffi.new('char[]', root_path.encode('utf-8'))

    task_id = pyextlib.create_task(ffi_exe_path, ffi_argv, ffi_envp,
        ffi_work_path,ffi_root_path, uid, gid, timelimit, memlimit)
    if task_id == 0:
        return None

    return task_id

def start_task(task_id, callback):
    global done_cb
    global task_callback

    task_callback[task_id] = callback
    return pyextlib.start_task(task_id, done_cb)
