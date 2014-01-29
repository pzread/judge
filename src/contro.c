#define _GNU_SOURCE

#define EXEC_STACKSIZE (16 * 1024)
#define COMPILE_MEMLIMIT (256 * 1024 * 1024)

#define CHALL_ST_AC 0
#define CHALL_ST_WA 1
#define CHALL_ST_TLE 1
#define CHALL_ST_MLE 2
#define CHALL_ST_RE 3
#define CHALL_ST_CE 4
#define CHALL_ST_ERR 5
#define CHALL_ST_PEND 100
#define CHALL_ST_COMP 101
#define CHALL_ST_RUN 102

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<limits.h>
#include<signal.h>
#include<sched.h>
#include<semaphore.h>
#include<sys/mman.h>

#include"fog.h"
#include"task.h"
#include"contro.h"

struct chall_data{
    int cont_id;
    sem_t *lock;
    int status;
};

static int challenge(void);
static void chall_dispatch(struct chall_data *cdata);
static int compile(struct chall_data *cdata);
static int exec_comp(struct chall_data *cdata);
static void handle_compsig(struct task *task,siginfo_t *siginfo);
static int run(struct chall_data *cdata);
static int exec_run(struct chall_data *cdata);
static void handle_runsig(struct task *task,siginfo_t *siginfo);

static int challenge(void){
    struct chall_data *cdata = NULL;
    int contid = -1; 

    if((cdata = malloc(sizeof(*cdata))) == NULL){
	goto err; 
    }

    if((cdata->lock = mmap(NULL,sizeof(*cdata->lock),PROT_READ | PROT_WRITE,
		    MAP_SHARED | MAP_ANONYMOUS,-1,0)) == NULL){
        goto err;
    }
    sem_init(cdata->lock,1,0);

    if((contid = fog_cont_alloc("comprun",COMPILE_MEMLIMIT)) < 0){
        goto err;
    }
    cdata->cont_id = contid;
    cdata->status = CHALL_ST_PEND;

    chall_dispatch(cdata);

    return 0;

err:

    if(cdata != NULL){
	free(cdata);

	if(cdata->lock != NULL){
	    sem_destroy(cdata->lock);
	    munmap(cdata->lock,sizeof(*cdata->lock));
	}
    }
    if(contid != -1){
	fog_cont_free(contid);
    }

    return -1;
}
static void chall_dispatch(struct chall_data *cdata){
    switch(cdata->status){
	case CHALL_ST_PEND:
	    cdata->status = CHALL_ST_COMP;
	    if(compile(cdata)){
		cdata->status = CHALL_ST_ERR;	
		goto end;
	    }

	    break;

	case CHALL_ST_COMP:
	    cdata->status = CHALL_ST_RUN;
	    if(run(cdata)){
		cdata->status = CHALL_ST_ERR;	
		goto end;
	    }

	    break;

	default:
	    goto end;
    }

    return;

end:

    printf("  %d\n",cdata->status);
}
static int compile(struct chall_data *cdata){
    int ret;

    void *stack = NULL;
    pid_t pid = 0;
    struct task *task = NULL;
    
    if(sem_getvalue(cdata->lock,&ret) || ret != 0){
	goto err;
    }

    if((stack = mmap(NULL,EXEC_STACKSIZE,PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,-1,0)) == NULL){
        goto err;
    }
    if((pid = clone((int (*)(void*))exec_comp,stack + EXEC_STACKSIZE,
		    SIGCHLD | CLONE_NEWNS | CLONE_NEWUTS |
		    CLONE_NEWIPC | CLONE_NEWNET,cdata)) < 0){
        goto err;
    }
    munmap(stack,EXEC_STACKSIZE);

    if((task = task_alloc(pid)) == NULL){
        goto err;
    }
    task->private = cdata;
    task->sig_handler = handle_compsig;

    sem_post(cdata->lock);

    return 0;

err:

    if(pid > 0){
        kill(pid,SIGKILL);
    }
    if(stack != NULL){
        munmap(stack,EXEC_STACKSIZE);
    }
    if(task != NULL){
        task_put(task);
    }

    return -1;
}
static int exec_comp(struct chall_data *cdata){
    char *args[] = {"g++","-O2","-std=c++0x",
        "/code/main.cpp","-o","/run/main",NULL};
    char *envp[] = {"PATH=/usr/bin",NULL};
    
    sem_wait(cdata->lock);

    if(fog_cont_attach(cdata->cont_id)){
        exit(1);
    }

    execve("/usr/bin/g++",args,envp);

    return 0;
}
static void handle_compsig(struct task *task,siginfo_t *siginfo){
    struct chall_data *cdata;

    if(siginfo->si_code != CLD_EXITED &&
	    siginfo->si_code != CLD_KILLED &&
	    siginfo->si_code != CLD_DUMPED){

	kill(task->pid,SIGKILL); 
	return;
    }

    cdata = (struct chall_data*)task->private;
    if(siginfo->si_code != CLD_EXITED || siginfo->si_status != 0){
	cdata->status = CHALL_ST_CE;
    }

    task->sig_handler = NULL;
    task_put(task);

    chall_dispatch(cdata);
}
static int run(struct chall_data *cdata){
    int ret;

    void *stack = NULL;
    pid_t pid = 0;
    struct task *task = NULL;

    if(sem_getvalue(cdata->lock,&ret) || ret != 0){
	goto err;
    }

    if((stack = mmap(NULL,EXEC_STACKSIZE,PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,-1,0)) == NULL){
        goto err;
    }
    if((pid = clone((int (*)(void*))exec_run,stack + EXEC_STACKSIZE,
		    SIGCHLD | CLONE_NEWNS | CLONE_NEWUTS |
		    CLONE_NEWIPC | CLONE_NEWNET,cdata)) < 0){
        goto err;
    }
    munmap(stack,EXEC_STACKSIZE);

    if((task = task_alloc(pid)) == NULL){
        goto err;
    }
    task->private = cdata;
    task->sig_handler = handle_runsig;

    sem_post(cdata->lock);

    return 0;

err:

    if(pid > 0){
        kill(pid,SIGKILL);
    }
    if(stack != NULL){
        munmap(stack,EXEC_STACKSIZE);
    }
    if(task != NULL){
        task_put(task);
    }

    return -1;

}
static int exec_run(struct chall_data *cdata){
    char *args[] = {"main",NULL};
    char *envp[] = {NULL};
    
    sem_wait(cdata->lock);

    if(fog_cont_attach(cdata->cont_id)){
        exit(1);
    }

    execve("/run/main",args,envp);

    return 0;
}
static void handle_runsig(struct task *task,siginfo_t *siginfo){
    struct chall_data *cdata;

    if(siginfo->si_code != CLD_EXITED &&
	    siginfo->si_code != CLD_KILLED &&
	    siginfo->si_code != CLD_DUMPED){

	kill(task->pid,SIGKILL); 
	return;
    }

    cdata = (struct chall_data*)task->private;
    if(siginfo->si_code != CLD_EXITED || siginfo->si_status != 0){
	cdata->status = CHALL_ST_RE;
    }else{
	cdata->status = CHALL_ST_AC;
    }

    task->sig_handler = NULL;
    task_put(task);

    chall_dispatch(cdata);
}

int contro_test(void){

    challenge();

    return 0;
}

int contro_init(void){
    if(fog_init()){
        return -1;
    }
    if(task_init()){
        return -1;
    }

    return 0;
}
