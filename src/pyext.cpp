#define LOG_PREFIX "pyext"

#include<cstring>
#include<cassert>
#include<csignal>
#include<queue>
#include<vector>
#include<unordered_map>
#include<fcntl.h>
#include<pwd.h>
#include<sys/mman.h>
#include<sys/stat.h>

#include"ev.h"
#include"utils.h"
#include"core.h"
#include"sandbox.h"

#define MAXEVENTS 1024

struct eventpair {
    int fd;
    int events;
};
struct taskstat {
    unsigned long utime;
    unsigned long stime;
    unsigned long peakmem;
    int detect_error;
};
typedef void (*func_pyext_stop_callback)(unsigned long id, taskstat stat);

static int evt_memfd;
static void *evt_mmap;
static std::unordered_map<int, ev_header*> poll_map;

extern "C" __attribute__((visibility("default"))) int init() {
    if(core_init()) {
	return -1;
    }

    if((evt_memfd = shm_open("/hypex_evt", O_RDWR | O_CREAT | O_TRUNC,
	0600)) < 0) {
	return -1;
    }
    assert(sizeof(eventpair) * MAXEVENTS == 8192);
    if(ftruncate(evt_memfd, sizeof(eventpair) * MAXEVENTS)) {
	return -1;
    }
    if((evt_mmap = mmap(NULL, sizeof(eventpair) * MAXEVENTS,
	PROT_READ | PROT_WRITE, MAP_SHARED, evt_memfd, 0)) == NULL) {
	return -1;
    }

    poll_map.clear();

    return evt_memfd;
}

extern "C" __attribute__((visibility("default")))
int ext_register(int fd, int events) {
    auto poll_it = poll_map.find(fd);
    ev_header *evhdr;

    if(poll_it == poll_map.end()) {
	evhdr = new ev_header();
	evhdr->fd = fd;
	evhdr->handler = NULL;
	poll_map[fd] = evhdr;
    } else {
	evhdr = poll_it->second;
    }

    return ev_register(evhdr, events);
}

extern "C" __attribute__((visibility("default")))
int ext_unregister(int fd) {
    auto poll_it = poll_map.find(fd);
    assert(poll_it != poll_map.end());

    return ev_unregister(poll_it->second);
}

extern "C" __attribute__((visibility("default")))
int ext_modify(int fd, int events) {
    auto poll_it = poll_map.find(fd);
    assert(poll_it != poll_map.end());

    return ev_modify(poll_it->second, events);
}

extern "C" __attribute__((visibility("default")))
int ext_poll(long timeout) {
    int i;
    int num;
    eventpair *ret = (eventpair*)evt_mmap;

    num = ev_poll(core_evdata, (int)timeout);

    for(i = 0;i < num && i < MAXEVENTS;i++) {
	ret[i].fd = core_evdata->polls[i].fd;
	ret[i].events = core_evdata->polls[i].events;
    }
    return i;
}

extern "C" __attribute__((visibility("default")))
unsigned long create_task(
    const char *exe_path,
    const char *argv[],
    const char *envp[],
    int stdin_fd,
    int stdout_fd,
    int stderr_fd,
    const char *work_path,
    const char *root_path,
    unsigned int uid,
    unsigned int gid,
    unsigned long timelimit,
    unsigned long memlimit,
    int restrict_level
) {
    int i;
    std::vector<std::string> vec_argv;
    std::vector<std::string> vec_envp;
    SandboxConfig config;

    for(i = 0;argv[i] != NULL;i++) {
	vec_argv.emplace_back(argv[i]);
    }
    for(i = 0;envp[i] != NULL;i++) {
	vec_envp.emplace_back(envp[i]);
    }

    config.stdin_fd = stdin_fd;
    config.stdout_fd = stdout_fd;
    config.stderr_fd = stdout_fd;
    config.work_path = work_path;
    config.root_path = root_path;
    config.uid = uid;
    config.gid = gid;
    config.timelimit = timelimit;
    config.memlimit = memlimit;
    config.restrict_level = (sandbox_restrict_level)restrict_level;

    auto nobody_pwd = getpwnam("nobody");
    if(nobody_pwd == NULL) {
	ERR("Can't get passwd of nobody\n");
	return 0;
    }
    config.uid_map.emplace_back(uid, uid);
    config.gid_map.emplace_back(gid, gid);
    config.uid_map.emplace_back(0, nobody_pwd->pw_uid);
    config.gid_map.emplace_back(0, nobody_pwd->pw_gid);

    return core_create_task(exe_path, vec_argv, vec_envp, config);
}

static void stop_task_callback(
    unsigned long id,
    const SandboxStat &stat,
    void *data
) {
    taskstat pystat;
    auto callback = (func_pyext_stop_callback)data;

    pystat.utime = stat.utime;
    pystat.stime = stat.stime;
    pystat.peakmem = stat.peakmem;
    pystat.detect_error = (int)stat.detect_error;
    callback(id, pystat);
}

extern "C" __attribute__((visibility("default")))
int start_task(unsigned long id, func_pyext_stop_callback callback) {
    return core_start_task(id, stop_task_callback, (void*)callback);
}
