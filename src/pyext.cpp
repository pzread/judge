//! @file pyext.cpp

//  Copyright 2016 PZ Read

//  Distributed under the MIT License.

/*

CFFI interface.

*/

#define LOG_PREFIX "pyext"

#include <ev.h>
#include <utils.h>
#include <core.h>
#include <sandbox.h>

#include<fcntl.h>
#include<pwd.h>
#include<sys/mman.h>
#include<sys/stat.h>
#include<cstring>
#include<cassert>
#include<csignal>
#include<string>
#include<queue>
#include<vector>
#include<unordered_map>

#define DLL_EXPORT extern "C" __attribute__ ((visibility("default")))
#define MAXEVENTS 1024

/*!

Task statistic for CFFI interface.

*/
struct taskstat {
    uint64_t utime;
    uint64_t stime;
    uint64_t peakmem;
    int detect_error;
};

/*!

Prototype of stop callback for CFFI interface.

*/
typedef void (*func_pyext_stop_callback)(uint64_t id, taskstat stat);

static uid_t old_euid = 0; //!< Old EUID before escalation.
static gid_t old_egid = 0; //!< Old EGID before escalation.
static std::unordered_map<int, ev_header*> poll_map; //!< Poll event map.

/*!

Escalate privilage while entering the extension.

*/
static void enter_pyext() {
    assert(old_egid == 0 && old_euid == 0);
    old_egid = getegid();
    old_euid = geteuid();
    if (seteuid(0) || setegid(0)) {
        ERR("Escalate privilage failed.");
    }
}

/*!

Recover privilage while leaving the extension.

*/
static void leave_pyext() {
    assert(old_egid != 0 && old_euid != 0);
    if (setegid(old_egid) || seteuid(old_euid)) {
        ERR("Drop privilage failed.");
    }
    old_egid = 0;
    old_euid = 0;
}

/*!

Initialize the extension.

*/
DLL_EXPORT int init() {
    enter_pyext();

    if (core_init()) {
        return -1;
    }
    poll_map.clear();

    leave_pyext();
    return 0;
}

/*!

Register a event.

@param fd File descriptor.
@param events Event flags.
@return 0 if success

*/
DLL_EXPORT int ext_register(int fd, int events) {
    auto poll_it = poll_map.find(fd);
    ev_header *evhdr;

    if (poll_it == poll_map.end()) {
        evhdr = new ev_header();
        evhdr->fd = fd;
        evhdr->handler = NULL;
        poll_map[fd] = evhdr;
    } else {
        evhdr = poll_it->second;
    }

    return ev_register(evhdr, events);
}

/*!

Unregister the event.

@param fd File descriptor.
@return 0 if success

*/
DLL_EXPORT int ext_unregister(int fd) {
    auto poll_it = poll_map.find(fd);
    assert(poll_it != poll_map.end());

    return ev_unregister(poll_it->second);
}

/*!

Modify the event.

@param fd File descriptor.
@param events Event flags.
@return 0 if success

*/
DLL_EXPORT int ext_modify(int fd, int events) {
    auto poll_it = poll_map.find(fd);
    assert(poll_it != poll_map.end());

    return ev_modify(poll_it->second, events);
}

/*!

Poll events.

@param pollpairs An array for storing event pairs.
@param timeout Timeout.
@return Number of events polled.

*/
DLL_EXPORT int ext_poll(ev_pollpair pollpairs[], int timeout) {
    int num;
    int i;

    enter_pyext();

    if ((num = ev_poll(core_evdata, timeout)) < 0) {
        return 0;
    }
    for (i = 0; i < num; i++) {
        pollpairs[i].fd = core_evdata->polls[i].fd;
        pollpairs[i].events = core_evdata->polls[i].events;
    }

    leave_pyext();
    return num;
}

/*!

Create a task.

@param exe_path Executable file path in the sandbox.
@param argv List of arguments.
@param envp List of environment variables.
@param stdin_fd Standard input file descriptor.
@param stdout_fd Standard output file descriptor.
@param stderr_fd Standard error file descriptor.
@param work_path Working directory in the sandbox.
@param root_path Root directory.
@param uid UID.
@param gid GID.
@param timelimit Timelimit.
@param memlimit Memlimit.
@param restrict_level Restriction level.
@return Task ID, -1 if failed.

*/
DLL_EXPORT uint64_t create_task(
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
    uint64_t timelimit,
    uint64_t memlimit,
    int restrict_level
) {
    int i;
    int ret;
    std::vector<std::string> vec_argv;
    std::vector<std::string> vec_envp;
    SandboxConfig config;

    for (i = 0; argv[i] != NULL; i++) {
        vec_argv.emplace_back(argv[i]);
    }
    for (i = 0; envp[i] != NULL; i++) {
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

    passwd nobody_pwdbuf, *nobody_pwd;
    char pwd_namebuf[4096];
    if (getpwnam_r("nobody", &nobody_pwdbuf, pwd_namebuf,
        sizeof(pwd_namebuf), &nobody_pwd)) {
        ERR("Can't get passwd of nobody\n");
        return 0;
    }
    // Direct map UID/GID of the sandbox.
    config.uid_map.emplace_back(uid, uid);
    config.gid_map.emplace_back(gid, gid);
    // Map UID/GID 0 in the sandbox to nobody at the outside.
    config.uid_map.emplace_back(0, nobody_pwd->pw_uid);
    config.gid_map.emplace_back(0, nobody_pwd->pw_gid);

    enter_pyext();
    ret = core_create_task(exe_path, vec_argv, vec_envp, config);
    leave_pyext();
    return ret;
}

/*!

Stop task callback.

@param id Task ID.
@param stat Sandbox statistic.
@param data Stop callback of CFFI.

*/
static void stop_task_callback(
    uint64_t id,
    const SandboxStat &stat,
    void *data
) {
    taskstat pystat;
    auto callback = (func_pyext_stop_callback)data;

    pystat.utime = stat.utime;
    pystat.stime = stat.stime;
    pystat.peakmem = stat.peakmem;
    pystat.detect_error = static_cast<int>(stat.detect_error);

    leave_pyext();
    callback(id, pystat);
    enter_pyext();
}

/*!

Start the task.

@param id Task ID.
@param callback Stop callback of CFFI.
@return 0 if success.

*/
DLL_EXPORT int start_task(uint64_t id, func_pyext_stop_callback callback) {
    int ret;

    enter_pyext();
    ret = core_start_task(id, stop_task_callback,
        reinterpret_cast<void*>(callback));
    leave_pyext();
    return ret;
}
