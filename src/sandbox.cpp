//! @file sandbox.cpp

//  Copyright 2016 PZ Read

//  Distributed under the MIT License.

/*

Sandbox controller, which is responsible to create, monitor, and destroy
sandboxes.

*/

#define LOG_PREFIX "sandbox"

#include <ev.h>
#include <utils.h>
#include <sandbox.h>
#include <core.h>

#include <unistd.h>
#include <sched.h>
#include <fcntl.h>
#include <grp.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/signal.h>
#include <sys/user.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <sys/signalfd.h>
#include <sys/resource.h>
#include <sys/mount.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <libcgroup.h>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstddef>
#include <cerrno>
#include <cstring>
#include <cassert>
#include <vector>
#include <string>
#include <unordered_map>
#include <queue>
#include <memory>

static int sigchld_sigfd; //!< Signal file desceiptor of SIGCHLD.
static ev_header sigchld_evhdr; //!< The ev_header of SIGCHLD;

/*!

Handle SIGCHLD signal.

@param evhdr Event ev_header.
@param events Event flags.

*/
static void sigchld_callback(struct ev_header *evhdr, uint32_t events) {
    signalfd_siginfo sigfdinfo;

    // Clean buffered data from the signal file descriptor.
    while (read(sigchld_sigfd, &sigfdinfo, sizeof(sigfdinfo)) > 0) {}

    siginfo_t siginfo;
    siginfo.si_pid = 0;
    while (!waitid(P_ALL, 0, &siginfo,
        WEXITED | WSTOPPED | WCONTINUED | WNOHANG)) {
        if (siginfo.si_pid == 0) {
            // There is no more waiting processes.
            break;
        }
        Sandbox::update_sandboxes(&siginfo);
    }
}

/*!

Initialize signal file descriptor, libcgroup, and signal mask.

*/
void sandbox_init() {
    sigset_t mask;

    cgroup_init();

    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &mask, NULL);
    sigchld_sigfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);

    sigchld_evhdr.fd = sigchld_sigfd;
    sigchld_evhdr.handler = sigchld_callback;
    ev_register(&sigchld_evhdr, EPOLLIN);
}

/*

Declare static members of the Sandbox class.

*/
uint64_t Sandbox::last_sandbox_id = 0;
std::unordered_map<pid_t, std::shared_ptr<Sandbox>> Sandbox::sandbox_map;
std::unordered_map<int, uint64_t> Sandbox::run_map;

/*!

Constructor. Initialize sandbox enviroments and configuration.

@param _exe_path Executable file path in the sandbox.
@param _argv Arguments.
@param _envp Environment variables.
@param _config Sandbox configuration.

*/
Sandbox::Sandbox(
    const std::string &_exe_path,
    const std::vector<std::string> &_argv,
    const std::vector<std::string> &_envp,
    const SandboxConfig &_config
) :
    state(SANDBOX_STATE_INIT),
    exe_path(_exe_path),
    argv(_argv),
    envp(_envp),
    config(_config),
    id(++last_sandbox_id)
{
    char cg_name[NAME_MAX + 1];
    char *memcg_path;
    char oom_path[PATH_MAX + 1];
    int oom_fd;
    char memevt_param[256];
    int memevt_fd;
    int forcetime_fd;

    cg = NULL;
    memcg = NULL;
    oom_fd = -1;
    memevt_fd = -1;
    forcetime_fd = -1;
    memevt_poll = NULL;
    forcetime_poll = NULL;
    suspend_fd = -1;

    try {
        // Create cgroup.
        snprintf(cg_name, sizeof(cg_name), "hypex_%lu", id);
        if ((cg = cgroup_new_cgroup(cg_name)) == NULL) {
            throw SandboxException("Create cgroup failed.");
        }
        if ((memcg = cgroup_add_controller(cg, "memory")) == NULL) {
            throw SandboxException("Create memory cgroup failed.");
        }
        cgroup_delete_cgroup(cg, 1);
        if (cgroup_create_cgroup(cg, 0)) {
            throw SandboxException("Add cgroup failed.");
        }

        // Set OOM cgroup event.
        if ((memevt_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK)) < 0) {
            throw SandboxException("Set memory event failed.");
        }
        if (cgroup_get_subsys_mount_point("memory", &memcg_path)) {
            throw SandboxException("Set memory event failed.");
        }
        snprintf(oom_path, sizeof(oom_path),
            "%s/hypex_%lu/memory.oom_control", memcg_path, id);
        free(memcg_path);
        if ((oom_fd = open(oom_path, O_RDONLY | O_CLOEXEC)) < 0) {
            throw SandboxException("Set memory event failed.");
        }
        snprintf(memevt_param, sizeof(memevt_param), "%d %d",
            memevt_fd, oom_fd);

        cgroup_set_value_uint64(memcg, "memory.swappiness", 0);
        cgroup_set_value_uint64(memcg, "memory.oom_control", 1);
        cgroup_set_value_uint64(memcg, "memory.limit_in_bytes",
            config.memlimit + 4096);
        cgroup_set_value_string(memcg, "cgroup.event_control", memevt_param);

        // Create cgroup physically.
        if (cgroup_modify_cgroup(cg)) {
            throw SandboxException("Set cgroup failed.");
        }
        close(oom_fd);
        oom_fd = -1;

        // Create force timer.
        if ((forcetime_fd = timerfd_create(CLOCK_MONOTONIC,
            TFD_NONBLOCK | TFD_CLOEXEC)) < 0) {
            throw SandboxException("Set force timer failed.");
        }

        //Register into event loop.
        memevt_poll = new sandbox_evpair();
        memevt_poll->hdr.fd = memevt_fd;
        memevt_poll->hdr.handler = memevt_handler;
        memevt_poll->id = id;
        forcetime_poll = new sandbox_evpair();
        forcetime_poll->hdr.fd = forcetime_fd;
        forcetime_poll->hdr.handler = forcetime_handler;
        forcetime_poll->id = id;
        ev_register(&memevt_poll->hdr, EPOLLIN);
        ev_register(&forcetime_poll->hdr, EPOLLIN);

        suspend_fd = eventfd(0, EFD_CLOEXEC);
        execve_count = 0;

    } catch (SandboxException &e) {
        if (oom_fd >= 0) {
            close(oom_fd);
        }
        if (memevt_fd >= 0) {
            close(memevt_fd);
        }
        if (memevt_poll != NULL) {
            ev_unregister(&memevt_poll->hdr);
            delete memevt_poll;
        }
        if (forcetime_fd >= 0) {
            close(forcetime_fd);
        }
        if (forcetime_poll != NULL) {
            ev_unregister(&forcetime_poll->hdr);
            delete forcetime_poll;
        }
        if (suspend_fd >= 0) {
            close(suspend_fd);
        }
        if (cg != NULL) {
            cgroup_delete_cgroup(cg, 1);
            cgroup_free(&cg);
        }

        throw;
    }
}

/*!

Destructor. Clean the sandbox.

*/
Sandbox::~Sandbox() noexcept {
    ev_unregister(&memevt_poll->hdr);
    close(memevt_poll->hdr.fd);
    delete memevt_poll;
    ev_unregister(&forcetime_poll->hdr);
    close(forcetime_poll->hdr.fd);
    delete forcetime_poll;
    close(suspend_fd);

    cgroup_delete_cgroup(cg, 1);
    cgroup_free(&cg);

    DBG("Sandbox %lu deleted\n", id);
}

/*!

Run the process in the sandbox.

@param _stop_callback Sandbox stop callback.

*/
void Sandbox::start(func_sandbox_stop_callback _stop_callback) {
    stop_callback = _stop_callback;
    stat.detect_error = SandboxStat::SANDBOX_STAT_NONE;

    sandbox_map[id] = shared_from_this();

    char *child_stack = new char[4 * 1024 * 1024];
    if ((child_pid = clone(sandbox_entry, child_stack + 4 * 1024 * 1024,
        CLONE_NEWIPC | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWNS
        | CLONE_NEWUSER | CLONE_NEWUTS | SIGCHLD,
        reinterpret_cast<void*>(id))) == -1) {
        throw SandboxException("Clone failed");
    }
    delete[] child_stack;

    state = SANDBOX_STATE_PRERUN;
    run_map[child_pid] = id;

    uint64_t suspend_val = 1;
    ptrace(PTRACE_ATTACH, child_pid, NULL, NULL);
    // Resume the process.
    if (write(suspend_fd, &suspend_val, sizeof(suspend_val))
        != sizeof(suspend_val)) {
        ERR("Resume process failed.\n");
    }
}

/*!

Called after the process is terminated. Call stop callback to report the process
statistic.

@param exit_error Whether the process is killed or exited with errors.

*/
void Sandbox::stop(bool exit_error) {
    if (state == SANDBOX_STATE_PRERUN) {
        stat.detect_error = SandboxStat::SANDBOX_STAT_INTERNALERR;
    }
    state = SANDBOX_STATE_STOP;

    if (stat.detect_error == SandboxStat::SANDBOX_STAT_NONE && exit_error) {
        stat.detect_error = SandboxStat::SANDBOX_STAT_EXITERR;
    }

    stop_callback(id);
}

/*!

Update the sandbox state.

@param siginfo The signal detail.

*/
void Sandbox::update_state(siginfo_t *siginfo) {
    // Check if the process is terminated.
    if (siginfo->si_code == CLD_EXITED) {
        if (siginfo->si_status == 0) {
            stop(false);
        } else {
            stop(true);
        }
        return;
    }
    if (siginfo->si_code == CLD_DUMPED || siginfo->si_code == CLD_KILLED) {
        stop(true);
        return;
    }

    if (state == SANDBOX_STATE_PRERUN) {
        // Ptrace attached, config cgroup, UID/GID mapping, start force timer.
        if (siginfo->si_code != CLD_TRAPPED || siginfo->si_status != SIGSTOP) {
            throw SandboxException("Trace task failed.");
        }
        if (ptrace(PTRACE_SETOPTIONS, child_pid, NULL,
            PTRACE_O_EXITKILL | PTRACE_O_TRACEEXIT | PTRACE_O_TRACESECCOMP |
            PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC)) {
            throw SandboxException("Trace task failed.");
        }

        char path[PATH_MAX + 1];
        FILE *f_uidmap = NULL;
        FILE *f_gidmap = NULL;

        try {
            snprintf(path, sizeof(path), "/proc/%d/uid_map", child_pid);
            if ((f_uidmap = fopen(path, "w")) == NULL) {
                throw SandboxException("Open uid_map failed.");
            }
            snprintf(path, sizeof(path), "/proc/%d/gid_map", child_pid);
            if ((f_gidmap = fopen(path, "w")) == NULL) {
                throw SandboxException("Open gid_map failed.");
            }
            for (auto uidpair : config.uid_map) {
                auto sdbx_uid = uidpair.first;
                auto parent_uid = uidpair.second;
                fprintf(f_uidmap, "%u %u 1\n", sdbx_uid, parent_uid);
            }
            for (auto gidpair : config.gid_map) {
                auto sdbx_gid = gidpair.first;
                auto parent_gid = gidpair.second;
                fprintf(f_gidmap, "%u %u 1\n", sdbx_gid, parent_gid);
            }
            fclose(f_uidmap);
            f_uidmap = NULL;
            fclose(f_gidmap);
            f_gidmap = NULL;

        } catch (SandboxException &e) {
            if (f_uidmap != NULL) {
                fclose(f_uidmap);
            }
            if (f_gidmap != NULL) {
                fclose(f_gidmap);
            }

            throw;
        }

        if (cgroup_attach_task_pid(cg, child_pid)) {
            throw SandboxException("Move to cgroup failed.");
        }

        state = SANDBOX_STATE_RUNNING;

        // Start timer after change state to running.
        itimerspec ts;
        ts.it_value.tv_sec = (config.timelimit * 10 + 1000) / 1000;
        ts.it_value.tv_nsec = ((config.timelimit * 10 + 1000) % 1000) * 1000000;
        ts.it_interval.tv_sec = 0;
        ts.it_interval.tv_nsec = 0;
        if (timerfd_settime(forcetime_poll->hdr.fd, 0, &ts, NULL)) {
            throw SandboxException("Start force timer failed.");
        }

        ptrace(PTRACE_CONT, child_pid, NULL, NULL);

    } else if (state == SANDBOX_STATE_RUNNING) {
        if (siginfo->si_code != CLD_TRAPPED) {
            throw SandboxException("Unexpected signal.");
        }

        if (siginfo->si_status == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
            if (execve_count > 0
                && config.restrict_level == SANDBOX_RESTRICT_HIGH) {
                //Not permit execve at high restriction level.
                terminate();
            }
            execve_count += 1;
            ptrace(PTRACE_CONT, child_pid, NULL, NULL);

        } else if (siginfo->si_status == (SIGTRAP | (PTRACE_EVENT_EXIT << 8))) {
            if (read_stat(&stat.utime, &stat.stime, &stat.peakmem)) {
                throw SandboxException("Read stat failed.");
            }
            ptrace(PTRACE_CONT, child_pid, NULL, NULL);

        } else if (siginfo->si_status
            == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))) {
            uint64_t nr;

            if (ptrace(PTRACE_GETEVENTMSG, child_pid, NULL, &nr)) {
                throw SandboxException("PTRACE_GETEVENTMSG failed.");
            }
            switch (nr) {
                case __NR_rt_sigprocmask:
                {
                    //Filter sigprocmask, deny any change on SIGVTALRM.
                    char path[PATH_MAX + 1];
                    int mem_fd;
                    struct user_regs_struct regs;
                    sigset_t sigset;

                    snprintf(path, sizeof(path), "/proc/%d/mem", child_pid);
                    if ((mem_fd = open(path, O_RDWR | O_CLOEXEC)) < 0) {
                        throw SandboxException("Can't open /proc/[pid]/mem");
                    }

                    ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
                    if (pread64(mem_fd, &sigset, sizeof(sigset), regs.rsi)
                        != sizeof(sigset)) {
                        throw SandboxException("Read sigprocmask failed.");
                    }
                    sigdelset(&sigset, SIGVTALRM);
                    if (pwrite64(mem_fd, &sigset, sizeof(sigset), regs.rsi)
                        != sizeof(sigset)) {
                        throw SandboxException("Write sigprocmask failed.");
                    }

                    close(mem_fd);
                    break;
                }
                default:
                    throw SandboxException("Unexpected signal.");
            }
            ptrace(PTRACE_CONT, child_pid, NULL, NULL);

        } else if ((siginfo->si_status & 0xF) == SIGTRAP) {
            // Hide other SIGTRAP signals.
            ptrace(PTRACE_CONT, child_pid, NULL, NULL);

        } else if (siginfo->si_status == SIGVTALRM) {
            // Timeout
            stat.detect_error = SandboxStat::SANDBOX_STAT_TIMEOUT;
            terminate();
            ptrace(PTRACE_CONT, child_pid, NULL, NULL);

        } else {
            // Passthrough other signals.
            ptrace(PTRACE_CONT, child_pid, NULL, siginfo->si_status);
        }
    }
}

/*!

Terminate the process.

*/
void Sandbox::terminate() {
    kill(child_pid, SIGKILL);
}

/*!

Install rlimit and user time limit.

*/
int Sandbox::install_limit() const {
    itimerval time;
    rlimit lim;

    lim.rlim_cur = 2147483647;
    lim.rlim_max = 2147483647;
    if (setrlimit(RLIMIT_STACK, &lim)) {
        return -1;
    }
    if (config.restrict_level == SANDBOX_RESTRICT_LOW) {
        lim.rlim_cur = 64;
        lim.rlim_max = 64;
        if (setrlimit(RLIMIT_NPROC, &lim)) {
            return -1;
        }
    } else if (config.restrict_level == SANDBOX_RESTRICT_HIGH) {
        lim.rlim_cur = 1;
        lim.rlim_max = 1;
        if (setrlimit(RLIMIT_NPROC, &lim)) {
            return -1;
        }
        lim.rlim_cur = 4;
        lim.rlim_max = 4;
        if (setrlimit(RLIMIT_NOFILE, &lim)) {
            return -1;
        }

        time.it_interval.tv_sec = 0;
        time.it_interval.tv_usec = 0;
        time.it_value.tv_sec = (config.timelimit + 1) / 1000;
        time.it_value.tv_usec = ((config.timelimit + 1) % 1000) * 1000;
        signal(SIGVTALRM, SIG_DFL);
        if (setitimer(ITIMER_VIRTUAL, &time, NULL)) {
            return -1;
        }
    }

    return 0;
}

/*!

Install seccomp filter.

*/
int Sandbox::install_filter() const {
    unsigned int upper_nr_limit = 0x40000000 - 1;
    struct sock_filter filter[] = {
        // Get arch
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
            (offsetof(struct seccomp_data, arch))),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, AUDIT_ARCH_X86_64, 0, 2),
        // Get syscall nr
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, nr))),
        BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, upper_nr_limit, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),

        // prctl
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_prctl, 0, 4),
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
            (offsetof(struct seccomp_data, args[0]))),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, PR_SET_SECCOMP, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EINVAL),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),

        // seccomp
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_seccomp, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EINVAL),

        // fork
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_fork, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EINVAL),

        // vfork
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_vfork, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EINVAL),

        // clone
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_clone, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EINVAL),

        // rt_sigaction
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_rt_sigaction, 0, 4),
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
            (offsetof(struct seccomp_data, args[0]))),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, SIGVTALRM, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EINVAL),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),

        // setitimer
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_setitimer, 0, 4),
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
            (offsetof(struct seccomp_data, args[0]))),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ITIMER_VIRTUAL, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EINVAL),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),

        // rt_sigprocmask
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_rt_sigprocmask, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRACE | __NR_rt_sigprocmask),

        // Other
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = (uint16_t)(sizeof(filter) / sizeof(*filter)),
        .filter = filter,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        return -1;
    }
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0);
}

/*!

Get the process statistic.

@param utime The pointer for storing user time (msec).
@param stime The pointer for storing system time (msec).
@param peakmem The pointer for storing maximum usage of memory (bytes).

*/
int Sandbox::read_stat(
    uint64_t *utime,
    uint64_t *stime,
    uint64_t *peakmem
) {
    char stat_path[PATH_MAX + 1];
    FILE *stat_f;
    char *memcg_path;
    char memuse_path[PATH_MAX + 1];
    FILE *memuse_f;

    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", child_pid);
    if ((stat_f = fopen(stat_path, "r")) == NULL) {
        return -1;
    }
    if (fscanf(stat_f,
        "%*d (%*[^)]) %*c %*d %*d %*d %*d %*d %*u %*d %*d %*d " \
        "%*d %lu %lu %*d %*d %*d %*d %*d %*d %*d %*d %*d " \
        "%*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d " \
        "%*d %*d %*d %*u %*d %*d %*d %*d %*d %*d %*d %*d "
        "%*d %*d %*d", utime, stime) != 2) {
        fclose(stat_f);
        return -1;
    }
    fclose(stat_f);

    *utime = (*utime * 1000UL) / sysconf(_SC_CLK_TCK);
    *stime = (*stime * 1000UL) / sysconf(_SC_CLK_TCK);

    if (cgroup_get_subsys_mount_point("memory", &memcg_path)) {
        return -1;
    }
    snprintf(memuse_path, sizeof(memuse_path),
        "%s/hypex_%lu/memory.max_usage_in_bytes", memcg_path, id);
    free(memcg_path);
    if ((memuse_f = fopen(memuse_path, "r")) == NULL) {
        return -1;
    }
    if (fscanf(memuse_f, "%lu", peakmem) != 1) {
        fclose(memuse_f);
        return -1;
    }
    fclose(memuse_f);

    return 0;
}

/*!

Update corresponding sandbox states.

@param siginfo The signal detail.

*/
void Sandbox::update_sandboxes(siginfo_t *siginfo) {
    auto id_it = run_map.find(siginfo->si_pid);
    if (id_it != run_map.end()) {
        auto sdbx_it = sandbox_map.find(id_it->second);
        assert(sdbx_it != sandbox_map.end());

        std::shared_ptr<Sandbox> sdbx = sdbx_it->second;
        try {
            sdbx->update_state(siginfo);
        } catch(SandboxException &e) {
            sdbx->stat.detect_error = SandboxStat::SANDBOX_STAT_INTERNALERR;
            sdbx->terminate();
        }
        if (sdbx->state == SANDBOX_STATE_STOP) {
            run_map.erase(id_it);
            sandbox_map.erase(sdbx->id);
        }
    }
}

/*!

OOM event handler.

@param hdr Event ev_header.
@param events Event flags.

*/
void Sandbox::memevt_handler(ev_header *hdr, uint32_t events) {
    auto sdbx_it = sandbox_map.find(
        reinterpret_cast<sandbox_evpair*>(hdr)->id);
    assert(sdbx_it != sandbox_map.end());
    std::shared_ptr<Sandbox> sdbx = sdbx_it->second;
    uint64_t count;

    if (read(hdr->fd, &count, sizeof(count)) != sizeof(count)) {
        return;
    }
    if (sdbx->state == SANDBOX_STATE_RUNNING) {
        sdbx->stat.detect_error = SandboxStat::SANDBOX_STAT_OOM;
        sdbx->terminate();
    }
}

/*!

Force timeout event handler.

@param hdr Event ev_header.
@param events Event flags.

*/
void Sandbox::forcetime_handler(ev_header *hdr, uint32_t events) {
    auto sdbx_it = sandbox_map.find(
        reinterpret_cast<sandbox_evpair*>(hdr)->id);
    assert(sdbx_it != sandbox_map.end());
    std::shared_ptr<Sandbox> sdbx = sdbx_it->second;
    uint64_t count;

    if (read(hdr->fd, &count, sizeof(count)) != sizeof(count)) {
        return;
    }
    if (sdbx->state == SANDBOX_STATE_RUNNING) {
        sdbx->stat.detect_error = SandboxStat::SANDBOX_STAT_FORCETIMEOUT;
        sdbx->terminate();
    }
}

/*!

The sandboxed process entry.

@param data Sandbox ID.

*/
int Sandbox::sandbox_entry(void *data) {
    unsigned int i;
    uint64_t id = (uint64_t)data;
    auto sdbx_it = sandbox_map.find(id);
    assert(sdbx_it != sandbox_map.end());
    std::shared_ptr<Sandbox> sdbx = sdbx_it->second;
    uint64_t suspend_val;

    // Wait for the resume event.
    if (read(sdbx->suspend_fd, &suspend_val, sizeof(suspend_val))
        != sizeof(suspend_val)) {
        _exit(-1);
    }

    if (setgroups(0, NULL)) {
        _exit(-1);
    }
    if (setresgid(sdbx->config.gid, sdbx->config.gid, sdbx->config.gid)) {
        _exit(-1);
    }
    if (setresuid(sdbx->config.uid, sdbx->config.uid, sdbx->config.uid)) {
        _exit(-1);
    }
    if (chroot(sdbx->config.root_path.c_str())) {
        _exit(-1);
    }
    if (chdir(sdbx->config.work_path.c_str())) {
        _exit(-1);
    }

    if (mount("proc", "/proc", "proc", 0, NULL)) {
        _exit(-1);
    }

    // Map file descriptors.
    std::vector<int> skipidxs;
    std::vector<int> tmpfds;
    for (i = 0; i < sdbx->config.fd_map.size(); i++) {
        // First map no conflict fd.
        if (fcntl(sdbx->config.fd_map[i].first, F_GETFD) == -1) {
            dup2(sdbx->config.fd_map[i].second, sdbx->config.fd_map[i].first);
        } else {
            skipidxs.emplace_back(i);
        }
    }
    for (auto idx : skipidxs) {
        // Move conflict fd to the empty one.
        tmpfds.emplace_back( \
            fcntl(sdbx->config.fd_map[idx].second, F_DUPFD_CLOEXEC, 0));
    }
    i = 0;
    for (auto idx : skipidxs) {
        // Override conflict fd.
        dup2(tmpfds[i], sdbx->config.fd_map[idx].first);
        close(tmpfds[i]);
        i += 1;
    }

    if (sdbx->install_limit()) {
        _exit(-1);
    }
    if (sdbx->config.restrict_level != SANDBOX_RESTRICT_LOW) {
        if (sdbx->install_filter()) {
            _exit(-1);
        }
    }

    char **c_argv = new char*[sdbx->argv.size() + 2];
    char **c_envp = new char*[sdbx->envp.size() + 1];
    auto c_exe_path = strdup(sdbx->exe_path.c_str());

    c_argv[0] = c_exe_path;
    for (i = 0; i < sdbx->argv.size(); i++) {
        c_argv[i + 1] = strdup(sdbx->argv[i].c_str());
    }
    c_argv[sdbx->argv.size() + 1] = NULL;

    for (i = 0; i < sdbx->envp.size(); i++) {
        c_envp[i] = strdup(sdbx->envp[i].c_str());
    }
    c_envp[sdbx->envp.size()] = NULL;

    execve(c_exe_path, c_argv, c_envp);
    return -1;
}
