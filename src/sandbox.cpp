#define LOG_PREFIX "sandbox"

#include<cstdio>
#include<cstdlib>
#include<cstdint>
#include<cstddef>
#include<cerrno>
#include<cstring>
#include<unistd.h>
#include<sys/wait.h>
#include<sys/time.h>
#include<sys/prctl.h>
#include<sys/ptrace.h>
#include<sys/syscall.h>
#include<sys/signal.h>
#include<sys/user.h>
#include<linux/seccomp.h>
#include<linux/filter.h>
#include<linux/audit.h>
#include<libcgroup.h>
#include<uv.h>

#include"utils.h"
#include"sandbox.h"
#include"core.h"

/*
static int install_filter() {
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

int Sandbox::trace_loop() {
    siginfo_t siginfo;
    
    if(waitid(P_PID, child_pid, &siginfo, WEXITED | WSTOPPED | WCONTINUED)) {
	return -1;
    }
    if(siginfo.si_code != CLD_TRAPPED || siginfo.si_status != SIGSTOP) {
	return -1;
    }
    if(ptrace(PTRACE_SETOPTIONS, child_pid, NULL,
	PTRACE_O_EXITKILL | PTRACE_O_TRACEEXIT | PTRACE_O_TRACESECCOMP |
	PTRACE_O_TRACESYSGOOD)) {
	return -1;
    }
    kill(child_pid, SIGCONT);
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);

    while(!waitid(P_PID, child_pid, &siginfo, WEXITED | WSTOPPED | WCONTINUED)) {
	if(siginfo.si_code == CLD_EXITED ||
	    siginfo.si_code == CLD_DUMPED ||
	    siginfo.si_code == CLD_KILLED) {
	    break;
	}
	if(siginfo.si_code != CLD_TRAPPED) {
	    return -1;
	}

	if(siginfo.si_status == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))) {
	    unsigned long nr;

	    if(ptrace(PTRACE_GETEVENTMSG, child_pid ,NULL, &nr)) {
		return -1;
	    }
	    switch(nr) {
		case __NR_rt_sigprocmask:
		    break;
		default:
		    return -1;
	    }
	    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
	} else {
	    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
	}
    }
    if(siginfo.si_code != CLD_EXITED) {
	DBG("Runtime Error\n");
    }

    return 0;
}
int Sandbox::start() {

    cgroup_set_value_uint64(memcg,"memory.swappiness",0);
    cgroup_set_value_uint64(memcg,"memory.oom_control",1);
    cgroup_set_value_uint64(memcg,"memory.limit_in_bytes",65536 * 1024);
    cgroup_create_cgroup(cg,0);


    if((child_pid = fork()) == 0) {
	ptrace(PTRACE_TRACEME, 0, NULL, NULL);
	kill(getpid(), SIGSTOP);

	if(install_filter()) {
	    printf("test\n");
	    _exit(-1);
	}

	char path[PATH_MAX + 1];
	strncpy(path, exepath.c_str(), sizeof(path));
	char *argv[] = {path, NULL};
	char *envp[] = {NULL};
	execve(argv[0], argv, envp);
	_exit(0);
    }
    if(trace_loop()) {
	ERR("Trace Error\n");
    }
    return 0;
}

int main(int argc, char *argv[]) {
    cgroup_init();
    auto cg = cgroup_new_cgroup("hypex");
    auto memcg = cgroup_add_controller(cg, "memory");

    Sandbox box(argv[1], memcg);
    box.start();

    cgroup_delete_cgroup(cg, 0);
    cgroup_free(&cg);
    return 0;
}
*/

static uv_signal_t sigchld_uvsig;

static void sigchld_callback(uv_signal_t *uvsig, int signo) {
    siginfo_t siginfo;
    while(!waitid(P_ALL, 0, &siginfo,
	WEXITED | WSTOPPED | WCONTINUED | WNOHANG)) {
	DBG("%d\n", siginfo.si_pid);
    }
}

void sandbox_init() {
    cgroup_init();
    uv_signal_init(core_uvloop, &sigchld_uvsig);
    uv_signal_start(&sigchld_uvsig, sigchld_callback, SIGCHLD);
}

Sandbox::Sandbox(const std::string &_exepath) : exepath(_exepath) {
    if((cg = cgroup_new_cgroup("hypex")) == NULL) {
	throw SandboxException("Create cgroup failed.");
    }
    if((memcg = cgroup_add_controller(cg, "memory")) == NULL) {
	throw SandboxException("Create memory cgroup failed.");
    }
}
void Sandbox::start() {
    INFO("Start task \"%s\".\n", exepath.c_str());
    if((child_pid = fork()) == 0) {
	char path[PATH_MAX + 1];
	strncpy(path, exepath.c_str(), sizeof(path));
	char *argv[] = {path, NULL};
	char *envp[] = {NULL};
	execve(path, argv, envp);
	_exit(0);
    }
}
