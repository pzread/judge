#define _GNU_SOURCE

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<signal.h>
#include<fcntl.h>
#include<unistd.h>
#include<sys/wait.h>
#include<sys/signalfd.h>

#include"khash/khash.h"
#include"ev.h"
#include"task.h"

KHASH_MAP_INIT_INT(ptr,void*)

static void handle_sigchld(struct ev_header *evhdr,uint32_t events);

static khash_t(ptr) *task_ht = NULL;
static struct ev_header sigchld_evhdr;
static int sigfd = -1;

int task_init(void){
    sigset_t sigset;
    
    task_ht = kh_init(ptr);

    sigemptyset(&sigset);
    sigaddset(&sigset,SIGCHLD);
    sigprocmask(SIG_BLOCK,&sigset,NULL);
    if((sigfd = signalfd(-1,&sigset,SFD_NONBLOCK | SFD_CLOEXEC)) < 0){
	goto err;
    }

    sigchld_evhdr.fd = sigfd;
    sigchld_evhdr.handler = handle_sigchld;
    if(ev_register(&sigchld_evhdr,EPOLLIN | EPOLLET)){
	goto err;
    }

    return 0;

err:

    if(task_ht != NULL){
	kh_destroy(ptr,task_ht);
    }
    if(sigfd >= 0){
	close(sigfd);
    }

    return -1;
}
static void handle_sigchld(struct ev_header *evhdr,uint32_t events){
    int ret;

    struct signalfd_siginfo sigfd_info[4];
    siginfo_t siginfo;
    struct task *task;

    while(1){
	ret = read(sigfd,sigfd_info,sizeof(*sigfd_info) * 4);
	if(ret < (int)sizeof(struct signalfd_siginfo)){
	    break;
	}
    }
    
    while(1){
	siginfo.si_pid = 0;
	if(waitid(P_ALL,0,&siginfo,WEXITED | WSTOPPED | WCONTINUED | WNOHANG) ||
		siginfo.si_pid == 0){
	    break;
	}

	if((task = task_getby_pid(siginfo.si_pid)) == NULL){
	    continue;
	}

	if(task->sig_handler != NULL){
	    task->sig_handler(task,&siginfo);
	}

	task_put(task);
    }
}

struct task* task_alloc(pid_t pid){
    int ret;

    struct task *task;
    khiter_t hit;

    if((task = malloc(sizeof(*task))) == NULL){
	return NULL;
    }

    task->refcount = 1;
    task->pid = pid;
    task->sig_handler = NULL;
    task->private = NULL;

    hit = kh_put(ptr,task_ht,task->pid,&ret);
    kh_value(task_ht,hit) = task;

    return task;
}
int task_get(struct task *task){
    task->refcount += 1;
    return 0;
}
int task_put(struct task *task){
    task->refcount -= 1; 

    if(task->refcount == 0){
	free(task);
    }

    return 0;
}
struct task* task_getby_pid(pid_t pid){
    khiter_t hit;
    struct task *task;

    if((hit = kh_get(ptr,task_ht,pid)) == kh_end(task_ht)){
	return NULL;
    }

    task = kh_value(task_ht,hit);
    task_get(task);

    return task;
}
