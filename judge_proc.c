#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<fcntl.h>
#include<dlfcn.h>
#include<limits.h>
#include<signal.h>
#include<sys/ioctl.h>
#include<sys/capability.h>
#include<sys/resource.h>
#include<sys/stat.h>

#include"judge.h"
#include"judge_proc.h"
#include"judge_com.h"

struct judge_proc_info* judge_proc_create(char *abspath,char *path,char *sopath,unsigned long timelimit,unsigned long memlimit){
    int ret;
    int i,j;

    struct stat st;
    struct judge_proc_info *proc_info;
    struct judge_check_info *check_info;

    if(stat(path,&st)){
	return (void*)-1;
    }
    if(!S_ISREG(st.st_mode)){
	return (void*)-1;
    }
    if(stat(sopath,&st)){
	return (void*)-1;
    }
    if(!S_ISREG(st.st_mode)){
	return (void*)-1;
    }

    proc_info = malloc(sizeof(struct judge_proc_info));
    check_info = malloc(sizeof(struct judge_check_info));
    if(proc_info == NULL || check_info == NULL){
	goto error;
    }

    proc_info->path[0] = '\0';
    strncat(proc_info->path,path,sizeof(proc_info->path));
    check_info->sopath[0] = '\0';
    strncat(check_info->sopath,sopath,sizeof(check_info->sopath));

    if((check_info->sohandle = dlopen(check_info->sopath,RTLD_NOW)) == NULL){
	goto error;
    }
    check_info->init_fn = dlsym(check_info->sohandle,"init_fn");
    check_info->run_fn = dlsym(check_info->sohandle,"run_fn");
    check_info->post_fn = dlsym(check_info->sohandle,"post_fn");
    check_info->clean_fn = dlsym(check_info->sohandle,"clean_fn");
    check_info->data = NULL;

    if(check_info->init_fn(abspath,&check_info->data)){
	goto error;
    }

    proc_info->name[NAME_MAX] = '\0';
    for(i = 0,j = 0;proc_info->path[i] != '\0' && j < NAME_MAX;i++){
	if(proc_info->path[i] == '/'){
	    j = 0;
	}else{
	    proc_info->name[j] = proc_info->path[i];
	    j++;
	}
    }
    proc_info->status = JUDGE_ERR;
    proc_info->name[j] = '\0';
    proc_info->pid = -1;
    proc_info->task = -1;
    proc_info->check_info = check_info;
    proc_info->timelimit = timelimit;
    proc_info->memlimit = memlimit;
    proc_info->runtime = 0L;
    proc_info->peakmem = 0L;

    return proc_info;

error:

    if(proc_info != NULL){
	free(proc_info);
    }
    if(check_info != NULL){
	free(check_info);
    }
    
    return (void*)-1;
}
int judge_proc_free(struct judge_proc_info *proc_info){
    dlclose(proc_info->check_info->sohandle);
    free(proc_info->check_info);
    free(proc_info);

    return 0;
}
static int proc_protect(struct judge_proc_info *proc_info){
    cap_t caps;
    struct rlimit limit;
    struct judge_com_proc_add com_proc_add;

    /*caps = cap_init();
    if(cap_set_file(proc_info->path,caps)){
	cap_free(caps);
	goto error;
    }
    cap_free(caps);*/

    limit.rlim_cur = 1;
    limit.rlim_max = limit.rlim_cur;
    prlimit(proc_info->pid,RLIMIT_NPROC,&limit,NULL);

    limit.rlim_cur = (proc_info->timelimit) / 1000L + 1L;
    limit.rlim_max = limit.rlim_cur;
    prlimit(proc_info->pid,RLIMIT_CPU,&limit,NULL);

    /*limit.rlim_cur = proc_info->memlimit * 1024L + 4096L * 128L;
    limit.rlim_max = limit.rlim_cur;
    prlimit(proc_info->pid,RLIMIT_AS,&limit,NULL);*/

    com_proc_add.path[0] = '\0';
    strncat(com_proc_add.path,proc_info->path,sizeof(com_proc_add.path));
    com_proc_add.pid = proc_info->pid;
    com_proc_add.memlimit = proc_info->memlimit * 1024L + 4096L * 128L;
    if(ioctl(judge_modfd,IOCTL_PROC_ADD,&com_proc_add)){
	return -1;
    }
    proc_info->task = com_proc_add.task;

    return 0;
}
int judge_proc_run(struct judge_proc_info *proc_info){
    int ret;

    struct judge_check_info *check_info;
    int waitstatus;
    struct judge_com_proc_get com_proc_get;
        
    check_info = proc_info->check_info;
    ret = 0;

    printf("proc1\n");

    if((proc_info->pid = fork()) == 0){
	char *argv[] = {NULL,NULL};
	char *envp[] = {NULL};

	if(check_info->run_fn(check_info->data)){
	    exit(-1);
	}
	setgid(99);
	setuid(99);
	kill(getpid(),SIGSTOP);

	argv[0] = proc_info->name;
	execve(proc_info->path,argv,envp);
    }

    printf("proc2\n");

    if(proc_info->pid == -1){
	ret = -1;
	goto clean;
    }
    waitpid(proc_info->pid,NULL,WUNTRACED);

    printf("proc3\n");

    if(proc_protect(proc_info)){
	ret = -1;
	goto clean;
    }

    printf("proc4\n");

    kill(proc_info->pid,SIGCONT);
    if(waitpid(proc_info->pid,&waitstatus,0) == -1){
	ret = -1;
	goto clean;
    }

    com_proc_get.task = proc_info->task;
    if(ioctl(judge_modfd,IOCTL_PROC_GET,&com_proc_get)){
	ret = -1;
	goto clean;
    }

    printf("proc5\n");

    proc_info->runtime = com_proc_get.runtime;
    proc_info->peakmem = com_proc_get.peakmem;

    if(com_proc_get.status != JUDGE_AC){
	proc_info->status = com_proc_get.status;
    }else if(proc_info->peakmem > (proc_info->memlimit * 1024L)){
	proc_info->status = JUDGE_MLE;
    }else if(proc_info->runtime > (proc_info->timelimit * 1000L)){
	proc_info->status = JUDGE_TLE;
    }else if(!WIFEXITED(waitstatus)){
	proc_info->status = JUDGE_RE;
    }else if(WEXITSTATUS(waitstatus) == JUDGE_RF){
	proc_info->status = JUDGE_RF;
    }else{
	proc_info->status = check_info->post_fn(check_info->data);
    }

    printf("proc6\n");

clean:

    if(proc_info->pid != -1){
	kill(proc_info->pid,SIGKILL);
    }
    if(proc_info->task != -1){
	ioctl(judge_modfd,IOCTL_PROC_DEL,proc_info->task);
    }
    check_info->clean_fn(check_info->data);

    printf("proc7\n");

    return ret;
}

