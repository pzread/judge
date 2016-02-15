#define LOG_PREFIX "sandbox"

#include<cstdio>
#include<cstdlib>
#include<cstdint>
#include<cstddef>
#include<cerrno>
#include<cstring>
#include<unordered_map>
#include<unistd.h>
#include<sched.h>
#include<grp.h>
#include<sys/wait.h>
#include<sys/time.h>
#include<sys/prctl.h>
#include<sys/ptrace.h>
#include<sys/syscall.h>
#include<sys/signal.h>
#include<sys/user.h>
#include<sys/eventfd.h>
#include<linux/seccomp.h>
#include<linux/filter.h>
#include<linux/audit.h>
#include<libcgroup.h>
#include<uv.h>

#include"utils.h"
#include"sandbox.h"
#include"core.h"

static uv_signal_t sigchld_uvsig;

static void sigchld_callback(uv_signal_t *uvsig, int signo) {
    siginfo_t siginfo;
    siginfo.si_pid = 0;
    while(!waitid(P_ALL, 0, &siginfo,
	WEXITED | WSTOPPED | WCONTINUED | WNOHANG)) {
	if(siginfo.si_pid == 0) {
	    break;
	}
	Sandbox::update_sandboxes(&siginfo);
    }
}

void sandbox_init() {
    cgroup_init();
    uv_signal_init(core_uvloop, &sigchld_uvsig);
    uv_signal_start(&sigchld_uvsig, sigchld_callback, SIGCHLD);
}

unsigned long Sandbox::last_sandbox_id = 0;
std::unordered_map<int, Sandbox*> Sandbox::run_map;

Sandbox::Sandbox(const std::string &_exe_path,
    const std::vector<std::string> &_argv,
    const std::vector<std::string> &_envp,
    const std::string &_work_path,
    const std::string &_root_path,
    unsigned int _uid,
    unsigned int _gid,
    const std::vector<std::pair<unsigned int, unsigned int>> &_uid_map,
    const std::vector<std::pair<unsigned int, unsigned int>> &_gid_map,
    unsigned long _timelimit,
    unsigned long _memlimit
) :
    id(++last_sandbox_id), state(SANDBOX_STATE_INIT),
    exe_path(_exe_path), argv(_argv), envp(_envp),
    work_path(_work_path), root_path(_root_path),
    uid(_uid), gid(_gid), uid_map(_uid_map), gid_map(_gid_map),
    timelimit(_timelimit), memlimit(_memlimit)
{
    char cg_name[NAME_MAX + 1];
    char *memcg_path;
    char oom_path[PATH_MAX + 1];
    int oom_fd;
    char memevt_param[256];

    cg = NULL;
    memcg = NULL;
    oom_fd = -1;
    memevt_fd = -1;

    try{ 
	snprintf(cg_name, sizeof(cg_name), "hypex_%lu", id);
	if((cg = cgroup_new_cgroup(cg_name)) == NULL) {
	    throw SandboxException("Create cgroup failed.");
	}
	if((memcg = cgroup_add_controller(cg, "memory")) == NULL) {
	    throw SandboxException("Create memory cgroup failed.");
	}
	cgroup_delete_cgroup(cg, 1);
	if(cgroup_create_cgroup(cg, 0)) {
	    throw SandboxException("Add cgroup failed.");
	}

	if((memevt_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK)) < 0) {
	    throw SandboxException("Set memory event failed.");
	}
	uv_poll_init(core_uvloop, &memevt_uvpoll, memevt_fd);
	((uv_handle_t*)&memevt_uvpoll)->data = this;
	uv_poll_start(&memevt_uvpoll, UV_READABLE, memevt_uvpoll_callback);

	if(cgroup_get_subsys_mount_point("memory", &memcg_path)) {
	    throw SandboxException("Set memory event failed.");
	}
	snprintf(oom_path, sizeof(oom_path),
	    "%s/hypex_%lu/memory.oom_control", memcg_path, id);
	free(memcg_path);
	if((oom_fd = open(oom_path, O_RDONLY | O_CLOEXEC)) < 0) {
	    throw SandboxException("Set memory event failed.");
	}
	snprintf(memevt_param, sizeof(memevt_param), "%d %d",
	    memevt_fd, oom_fd);

	cgroup_set_value_uint64(memcg, "memory.swappiness", 0);
	cgroup_set_value_uint64(memcg, "memory.oom_control", 1);
	cgroup_set_value_uint64(memcg, "memory.limit_in_bytes",
	    memlimit + 4096);
	cgroup_set_value_string(memcg, "cgroup.event_control", memevt_param);

	if(cgroup_modify_cgroup(cg)) {
	    throw SandboxException("Set cgroup failed.");
	}
	close(oom_fd);
	oom_fd = -1;

	uv_timer_init(core_uvloop, &force_uvtimer);
	((uv_handle_t*)&force_uvtimer)->data = this;

    } catch(SandboxException &e) {
	if(oom_fd >= 0) {
	    close(oom_fd);
	}
	if(memevt_fd >= 0) {
	    uv_poll_stop(&memevt_uvpoll);
	    close(memevt_fd);
	}
        if(cg != NULL) {
	    cgroup_delete_cgroup(cg, 1);
	    cgroup_free(&cg);
	}
	throw e;
    }
}

Sandbox::~Sandbox() {
    uv_poll_stop(&memevt_uvpoll);
    close(memevt_fd);
    cgroup_delete_cgroup(cg, 1);
    cgroup_free(&cg);
}

void Sandbox::start() {
    INFO("Start task \"%s\".\n", exe_path.c_str());

    char *child_stack = new char[4 * 1024 * 1024];
    if((child_pid = clone(sandbox_entry, child_stack + 4 * 1024 * 1024,
	CLONE_NEWIPC | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWNS
	| CLONE_NEWUSER | CLONE_NEWUTS | SIGCHLD, this)) == -1) {
	throw SandboxException("Clone failed");
    }
    delete[] child_stack;

    run_map[child_pid] = this;
    state = SANDBOX_STATE_PRERUN;
}

void Sandbox::stop() {
    if(state == SANDBOX_STATE_PRERUN) {
	run_map.erase(child_pid);
    } else if(state == SANDBOX_STATE_RUNNING) {
	run_map.erase(child_pid);
	uv_timer_stop(&force_uvtimer);
    }
    state = SANDBOX_STATE_STOP;
}

void Sandbox::update_state(siginfo_t *siginfo) {
    if(siginfo->si_code == CLD_EXITED) {
	if(siginfo->si_status == 0) {
	    statistic(false);
	} else {
	    statistic(false);
	}
	return;
    }
    if(siginfo->si_code == CLD_DUMPED || siginfo->si_code == CLD_KILLED) {
	statistic(true);
	return;
    }

    if(state == SANDBOX_STATE_PRERUN) {
	if(siginfo->si_code != CLD_TRAPPED || siginfo->si_status != SIGSTOP) {
	    throw SandboxException("Trace task failed.");
	}
	if(ptrace(PTRACE_SETOPTIONS, child_pid, NULL,
	    PTRACE_O_EXITKILL | PTRACE_O_TRACEEXIT | PTRACE_O_TRACESECCOMP |
	    PTRACE_O_TRACESYSGOOD)) {
	    throw SandboxException("Trace task failed.");
	}

	char path[PATH_MAX + 1];
	FILE *f_uidmap;
	FILE *f_gidmap;

	snprintf(path, sizeof(path), "/proc/%d/uid_map", child_pid);
	if((f_uidmap = fopen(path, "w")) == NULL) {
	    throw SandboxException("Open uid_map failed.");
	}
	snprintf(path, sizeof(path), "/proc/%d/gid_map", child_pid);
	if((f_gidmap = fopen(path, "w")) == NULL) {
	    throw SandboxException("Open gid_map failed.");
	}
	for(auto uidpair : uid_map) {
	    auto sdbx_uid = uidpair.first;
	    auto parent_uid = uidpair.second;
	    fprintf(f_uidmap, "%u %u 1\n", sdbx_uid, parent_uid);
	}
	for(auto gidpair : gid_map) {
	    auto sdbx_gid = gidpair.first;
	    auto parent_gid = gidpair.second;
	    fprintf(f_gidmap, "%u %u 1\n", sdbx_gid, parent_gid);
	}
	fclose(f_uidmap);
	fclose(f_gidmap);

	uv_timer_start(&force_uvtimer, force_uvtimer_callback,
	    timelimit * 4 + 1000, 0);
	if(cgroup_attach_task_pid(cg, child_pid)) {
	    throw SandboxException("Move to cgroup failed.");
	}

	kill(child_pid, SIGCONT);
	ptrace(PTRACE_CONT, child_pid, NULL, NULL);
	state = SANDBOX_STATE_RUNNING;

    } else if(state == SANDBOX_STATE_RUNNING) {
	if(siginfo->si_code != CLD_TRAPPED) {
	    throw SandboxException("Unexpected signal.");
	    return;
	}

	if(siginfo->si_status == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))) {
	    unsigned long nr;

	    if(ptrace(PTRACE_GETEVENTMSG, child_pid ,NULL, &nr)) {
		throw SandboxException("PTRACE_GETEVENTMSG failed.");
		return;
	    }
	    switch(nr) {
		case __NR_rt_sigprocmask:
		{
		    char path[PATH_MAX + 1];
		    int mem_fd;
		    struct user_regs_struct regs;
		    sigset_t sigset;

		    snprintf(path, sizeof(path), "/proc/%d/mem", child_pid);
		    if((mem_fd = open(path, O_RDWR | O_CLOEXEC)) < 0) {
			throw SandboxException("Can't open /proc/[pid]/mem");
		    }

		    ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
		    if(pread64(mem_fd, &sigset, sizeof(sigset), regs.rsi)
			!= sizeof(sigset)) {
			throw SandboxException("Read sigprocmask failed.");
		    }
		    sigdelset(&sigset,SIGVTALRM);
		    if(pwrite64(mem_fd, &sigset, sizeof(sigset), regs.rsi)
			!= sizeof(sigset)) {
			throw SandboxException("Write sigprocmask failed.");
		    }

		    close(mem_fd);
		    break;
		}
		default:
		    throw SandboxException("Unexpected signal.");
		    return;
	    }
	    ptrace(PTRACE_CONT, child_pid, NULL, NULL);

	} else if(siginfo->si_status == SIGCONT
	    || (siginfo->si_status & 0xF) == SIGTRAP) {
	    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
	} else if(siginfo->si_status == SIGVTALRM
	    || siginfo->si_status == SIGSTOP) {
	    terminate();
	    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
	} else {
	    ptrace(PTRACE_CONT, child_pid, NULL, siginfo->si_status);
	}
    }
}

void Sandbox::statistic(bool exit_error) {
    INFO("Task finished.\n");
    stop();
}

void Sandbox::terminate() {
    kill(child_pid, SIGKILL);
}

int Sandbox::install_limit() const {
    struct itimerval time;

    time.it_interval.tv_sec = 0;
    time.it_interval.tv_usec = 0;
    time.it_value.tv_sec = (timelimit + 1) / 1000;
    time.it_value.tv_usec = ((timelimit + 1) % 1000) * 1000;
    signal(SIGVTALRM, SIG_DFL);
    return setitimer(ITIMER_VIRTUAL, &time, NULL);
}

int Sandbox::install_filter() const {
    unsigned int upper_nr_limit = 0x40000000 - 1;
    struct sock_filter filter[] = {
	//get arch
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
	    (offsetof(struct seccomp_data, arch))),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, AUDIT_ARCH_X86_64, 0, 2),
	//get syscall nr
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, nr))),
	BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, upper_nr_limit, 0, 1),
	BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),

	//prctl
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_prctl, 0, 4),
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
	    (offsetof(struct seccomp_data, args[0]))),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, PR_SET_SECCOMP, 0, 1),
	BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EINVAL),
	BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),

	//seccomp
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_seccomp, 0, 1),
	BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EINVAL),

	//rt_sigaction
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_rt_sigaction, 0, 4),
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
	    (offsetof(struct seccomp_data, args[0]))),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, SIGVTALRM, 0, 1),
	BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EINVAL),
	BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),

	//setitimer
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_setitimer, 0, 4),
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
	    (offsetof(struct seccomp_data, args[0]))),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ITIMER_VIRTUAL, 0, 1),
	BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EINVAL),
	BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),

	//rt_sigprocmask
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_rt_sigprocmask, 0, 1),
	BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRACE | __NR_rt_sigprocmask),

	//other
	BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
	.len = (unsigned short)(sizeof(filter) / sizeof(*filter)),
	.filter = filter,
    };
    if(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
	return -1;
    }
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0);
}

void Sandbox::update_sandboxes(siginfo_t *siginfo) {
    auto sdbx_it = run_map.find(siginfo->si_pid);
    if(sdbx_it != run_map.end()) {
	auto sdbx = sdbx_it->second;
	try {
	    sdbx->update_state(siginfo);
	} catch(SandboxException &e) {
	    sdbx->terminate();   
	}
    }
}

void Sandbox::memevt_uvpoll_callback(
    uv_poll_t *uvpoll,
    int status,
    int events
) {
    Sandbox *sdbx = (Sandbox*)((uv_handle_t*)uvpoll)->data;
    unsigned long count;

    if(read(sdbx->memevt_fd, &count, sizeof(count)) != sizeof(count)) {
	return;
    }
    sdbx->terminate();
}

void Sandbox::force_uvtimer_callback(uv_timer_t *uvtimer) {
    ((Sandbox*)((uv_handle_t*)uvtimer)->data)->terminate();
}

int Sandbox::sandbox_entry(void *data) {
    Sandbox *sdbx = (Sandbox*)data;

    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    kill(getpid(), SIGSTOP);

    if(setgroups(0, NULL)) {
	_exit(-1);
    }
    if(setresgid(sdbx->gid, sdbx->gid, sdbx->gid)) {
	_exit(-1);
    }
    if(setresuid(sdbx->uid, sdbx->uid, sdbx->uid)) {
	_exit(-1);
    }
    if(chroot(sdbx->root_path.c_str())) {
	_exit(-1);
    }
    if(chdir(sdbx->work_path.c_str())) {
	_exit(-1);
    }
    if(sdbx->install_limit()) {
	_exit(-1);
    }
    if(sdbx->install_filter()) {
	_exit(-1);
    }

    unsigned int i;
    char **c_argv = new char*[sdbx->argv.size() + 2];
    char **c_envp = new char*[sdbx->envp.size() + 1];
    auto c_exe_path = strdup(sdbx->exe_path.c_str());

    c_argv[0] = c_exe_path;
    for(i = 0;i < sdbx->argv.size();i++) {
	c_argv[i + 1] = strdup(sdbx->argv[i].c_str());
    }
    c_argv[sdbx->argv.size() + 1] = NULL;

    for(i = 0;i < sdbx->envp.size();i++) {
	c_envp[i] = strdup(sdbx->envp[i].c_str());
    }
    c_envp[sdbx->envp.size()] = NULL;

    execve(c_exe_path, c_argv, c_envp);
    _exit(-1);
    return 0;
}
