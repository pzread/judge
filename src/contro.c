#define _GNU_SOURCE

#define EXEC_STACKSIZE (16 * 1024)
#define COMPILE_MEMLIMIT (256 * 1024 * 1024)

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

struct compile_data{
    int cont_id;
    sem_t *lock;
};

static int exec_compile(struct compile_data *cdata);
static void handle_end_compile(struct task *task,siginfo_t *siginfo);

static int compile(){
    int contid = -1; 
    struct compile_data *cdata = NULL;
    void *stack = NULL;
    pid_t pid = 0;
    struct task *task = NULL;

    if((contid = fog_cont_alloc("compile",COMPILE_MEMLIMIT)) < 0){
        goto err;
    }

    if((cdata = malloc(sizeof(*cdata))) == NULL){
        goto err;
    }
    if((cdata->lock = mmap(NULL,sizeof(*cdata->lock),PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_ANONYMOUS,-1,0)) == NULL){
        goto err;
    }
    cdata->cont_id = contid;
    sem_init(cdata->lock,1,0);
    
    if((stack = mmap(NULL,EXEC_STACKSIZE,PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,-1,0)) == NULL){
        goto err;
    }
    if((pid = clone((int (*)(void*))exec_compile,stack + EXEC_STACKSIZE,
		    SIGCHLD | CLONE_NEWNS | CLONE_NEWUTS |
		    CLONE_NEWIPC | CLONE_NEWNET,cdata)) < 0){
        goto err;
    }
    munmap(stack,EXEC_STACKSIZE);

    if((task = task_alloc(pid)) == NULL){
        goto err;
    }
    task->private = cdata;
    task->sig_handler = handle_end_compile;

    sem_post(cdata->lock);

    return 0;

err:

    if(pid > 0){
        kill(pid,SIGKILL);
    }
    if(contid != -1){
        fog_cont_free(contid);
    }
    if(cdata != NULL){
        sem_destroy(cdata->lock);
        free(cdata);
    }
    if(stack != NULL){
        munmap(stack,EXEC_STACKSIZE);
    }
    if(task != NULL){
        task_put(task);
    }

    return -1;
}
static int exec_compile(struct compile_data *cdata){
    char *args[] = {"g++","-O2","-std=c++0x",
        "/code/1/main.cpp","-o","/code/1/main",NULL};
    char *envp[] = {"PATH=/usr/bin",NULL};
    
    sem_wait(cdata->lock);

    if(fog_cont_attach(cdata->cont_id)){
        exit(1);
    }

    execve("/usr/bin/g++",args,envp);
    return 0;
}
static void handle_end_compile(struct task *task,siginfo_t *siginfo){
    struct compile_data *cdata;
    struct cont_stat contst;

    cdata = (struct compile_data*)task->private;

    fog_cont_stat(cdata->cont_id,&contst);
    fog_cont_free(cdata->cont_id);

    task->private = NULL;
    task_put(task);

    sem_destroy(cdata->lock);
    free(cdata);
}

int contro_test(void){

    compile();

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
