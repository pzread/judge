#define LOG_PREFIX "sandbox"

#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<stddef.h>
#include<errno.h>
#include<fcntl.h>
#include<limits.h>
#include<unistd.h>
#include<signal.h>
#include<sys/wait.h>
#include<sys/time.h>
#include<sys/user.h>
#include<sys/prctl.h>
#include<sys/ptrace.h>
#include<sys/syscall.h>
#include<linux/audit.h>
#include<linux/filter.h>
#include<linux/seccomp.h>
#include<libcgroup.h>
#include"utils.h"

static int read_stat(
	pid_t pid,
	unsigned long *utime,
	unsigned long *stime,
	unsigned long *vmem
) {
	char statpath[PATH_MAX + 1];
	FILE *f;

	snprintf(statpath,sizeof(statpath),"/proc/%u/stat",pid);
	if((f = fopen(statpath,"r")) == NULL) {
		return -1;
	}
	fscanf(f,"%*d (%*[^)]) %*c %*d %*d %*d %*d %*d %*u %*d %*d %*d " \
		"%*d %lu %lu %*d %*d %*d %*d %*d %*d %*d %lu %*d " \
		"%*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d " \
		"%*d %*d %*d %*u %*d %*d %*d %*d %*d %*d %*d %*d "
		"%*d %*d %*d",utime,stime,vmem);
	fclose(f);
	*utime = (*utime * 1000UL) / sysconf(_SC_CLK_TCK);
	*stime = (*stime * 1000UL) / sysconf(_SC_CLK_TCK);
	return 0;
}

static int install_limit(unsigned long msec) {
	int ret;
	struct itimerval time;

	time.it_interval.tv_sec = 0;
	time.it_interval.tv_usec = 0;
	time.it_value.tv_sec = (msec + 1) / 1000;
	time.it_value.tv_usec = ((msec + 1) % 1000) * 1000;
	signal(SIGVTALRM,SIG_DFL);
	if((ret = setitimer(ITIMER_VIRTUAL,&time,NULL))) {
		return ret;
	}
	/*time.it_interval.tv_sec = 0;
	time.it_interval.tv_usec = 0;
	time.it_value.tv_sec = msec * 4 / 1000;
	time.it_value.tv_usec = ((msec * 4) % 1000) * 1000;
	signal(SIGALRM,SIG_DFL);
	if((ret = setitimer(ITIMER_REAL,&time,NULL))) {
		return ret;
	}*/

	return 0;
}
static int install_filter() {
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
				(offsetof(struct seccomp_data,arch))),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,AUDIT_ARCH_X86_64,1,0),
		BPF_STMT(BPF_RET + BPF_K,SECCOMP_RET_KILL),

		//get syscall nr
		BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
				(offsetof(struct seccomp_data,nr))),

		//prctl
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,__NR_prctl,0,4),
		BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
				(offsetof(struct seccomp_data,args[0]))),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,PR_SET_SECCOMP,0,1),
		BPF_STMT(BPF_RET + BPF_K,SECCOMP_RET_ERRNO | EINVAL),
		BPF_STMT(BPF_RET + BPF_K,SECCOMP_RET_ALLOW),

		//rt_sigaction
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,__NR_rt_sigaction,0,4),
		BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
				(offsetof(struct seccomp_data,args[0]))),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,SIGVTALRM,0,1),
		BPF_STMT(BPF_RET + BPF_K,SECCOMP_RET_ERRNO | EINVAL),
		BPF_STMT(BPF_RET + BPF_K,SECCOMP_RET_ALLOW),

		//setitimer
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,__NR_setitimer,0,4),
		BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
				(offsetof(struct seccomp_data,args[0]))),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,ITIMER_VIRTUAL,0,1),
		BPF_STMT(BPF_RET + BPF_K,SECCOMP_RET_ERRNO | EINVAL),
		BPF_STMT(BPF_RET + BPF_K,SECCOMP_RET_ALLOW),
		
		//rt_sigprocmask
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,__NR_rt_sigprocmask,0,1),
		BPF_STMT(
			BPF_RET + BPF_K,
			SECCOMP_RET_TRACE | __NR_rt_sigprocmask),

		//other
		BPF_STMT(BPF_RET + BPF_K,SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter) / sizeof(*filter)),
		.filter = filter,
	};
	return prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&prog,0,0);
}
static int trace_loop(pid_t pid) {
	siginfo_t siginfo;
	int stage = 0;
	char mempath[PATH_MAX + 1];
	int memfd;

	while(waitid(P_PID,pid,&siginfo,WEXITED | WSTOPPED | WCONTINUED) == 0) {
		if(stage == 0) {
			if(siginfo.si_code != CLD_TRAPPED) {
				return -1;
			}
			if(ptrace(
				PTRACE_SETOPTIONS,
				pid,
				NULL,
				PTRACE_O_EXITKILL |
				PTRACE_O_TRACEEXIT |
				PTRACE_O_TRACESECCOMP
			)) {
				return -1;
			}
			snprintf(mempath,sizeof(mempath),"/proc/%u/mem",pid);
			memfd = open(mempath,O_RDWR | O_CLOEXEC);
			ptrace(PTRACE_CONT,pid,NULL,NULL);
			stage = 1;
			dbg("start\n");
		} else if(siginfo.si_code == CLD_TRAPPED) {
			if(siginfo.si_status == (
				SIGTRAP | (PTRACE_EVENT_SECCOMP << 8)
			)) {
				unsigned long nr;
				struct user_regs_struct regs;
				sigset_t sigset;

				ptrace(PTRACE_GETEVENTMSG,pid,NULL,&nr);
				if(nr == __NR_rt_sigprocmask) {
					ptrace(PTRACE_GETREGS,pid,NULL,&regs);
					pread(memfd,
						&sigset,
						sizeof(sigset),
						regs.rsi);
					sigdelset(&sigset,SIGVTALRM);
					pwrite(memfd,
						&sigset,
						sizeof(sigset),
						regs.rsi);
				}
				ptrace(PTRACE_CONT,pid,NULL,NULL);
			} else if(siginfo.si_status == (
				SIGTRAP | (PTRACE_EVENT_EXIT << 8)
			)) {
				unsigned long utime,stime,vmem;
				read_stat(pid,&utime,&stime,&vmem);
				dbg("ut:%lu st:%lu vm:%lu\n",utime,stime,vmem);
				ptrace(PTRACE_CONT,pid,NULL,NULL);
			} else {
				ptrace(PTRACE_CONT,
					pid,
					NULL,
					siginfo.si_status & 0xFF);
			}
		} else if(siginfo.si_code == CLD_KILLED ||
			siginfo.si_code == CLD_DUMPED ||
			siginfo.si_code == CLD_STOPPED
		) {
			dbg("error exit\n");
		} else if(siginfo.si_code == CLD_EXITED) {
			dbg("general exit\n");
		} else {
			err("unexcepted si_code %d\n",siginfo.si_code);
		}
	}
	return 0;
}

int main(int argc,char *argv[]){
	pid_t pid;

	struct cgroup *cg;
	struct cgroup_controller *cgcl;
	char *clpath,tpath[PATH_MAX + 1];
	FILE *f;
	int oom;

	if(argc < 2) {
		return 0;
	}

	cgroup_init();
	cg = cgroup_new_cgroup("hypex");
	cgcl = cgroup_add_controller(cg,"memory");
	cgroup_set_value_uint64(cgcl,"memory.swappiness",0);
	cgroup_set_value_uint64(cgcl,"memory.oom_control",1);
	cgroup_set_value_uint64(cgcl,"memory.limit_in_bytes",65536 * 1024);
	cgroup_create_cgroup(cg,0);
	
	if((pid = fork()) == 0) {
		char *child_argv[] = {argv[1],NULL};
		char *child_envp[] = {NULL};

		ptrace(PTRACE_TRACEME,0,NULL,NULL);

		if(install_limit(3000)) {
			_exit(0);
		}
		if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)) {
			_exit(0);
		}
		if(install_filter()) {
			_exit(0);
		}

		cgroup_attach_task(cg);
		cgroup_free(&cg);

		execve(argv[1],child_argv,child_envp);
		_exit(0);
	}

	trace_loop(pid);

	cgroup_get_subsys_mount_point("memory",&clpath);
	snprintf(tpath,sizeof(tpath),"%s/hypex/memory.oom_control",clpath);
	f = fopen(tpath,"r");
	fscanf(f,"oom_kill_disable %*d\n");
	fscanf(f,"under_oom %d\n",&oom);
	dbg("%d\n",oom);
	fclose(f);
	free(clpath);

	cgroup_delete_cgroup(cg,0);
	cgroup_free(&cg);

	return 0;
}
