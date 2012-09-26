#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<fcntl.h>
#include<dlfcn.h>
#include<limits.h>
#include<signal.h>
#include<errno.h>
#include<sys/ioctl.h>
#include<sys/capability.h>
#include<sys/resource.h>
#include<sys/stat.h>

#include"judge_app.h"
#include"judge_com.h"
#include"judge.h"

struct judge_proc_info* judge_init(char *path,char *sopath,unsigned long timelimit,unsigned long memlimit){
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

    proc_info->path[PATH_MAX] = '\0';
    strncpy(proc_info->path,path,PATH_MAX);
    check_info->sopath[PATH_MAX] = '\0';
    strncpy(check_info->sopath,sopath,PATH_MAX);

    if((check_info->sohandle = dlopen(check_info->sopath,RTLD_NOW)) == NULL){
	goto error;
    }
    check_info->init_fn = dlsym(check_info->sohandle,"init_fn");
    check_info->run_fn = dlsym(check_info->sohandle,"run_fn");
    check_info->post_fn = dlsym(check_info->sohandle,"post_fn");
    check_info->clean_fn = dlsym(check_info->sohandle,"clean_fn");
    check_info->private = NULL;

    proc_info->name[NAME_MAX] = '\0';
    for(i = 0,j = 0;proc_info->path[i] != '\0' && j < NAME_MAX;i++){
	if(proc_info->path[i] == '/'){
	    j = 0;
	}else{
	    proc_info->name[j] = proc_info->path[i];
	    j++;
	}
    }
    proc_info->state = JUDGE_ERR;
    proc_info->name[j] = '\0';
    proc_info->pid = -1;
    proc_info->task = -1;
    proc_info->check_info = check_info;
    proc_info->timelimit = timelimit;
    proc_info->memlimit = memlimit;

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
static int judge_run_init(struct judge_proc_info *proc_info){
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

    limit.rlim_cur = proc_info->memlimit * 1024L + 4096L * 128L;
    limit.rlim_max = limit.rlim_cur;
    prlimit(proc_info->pid,RLIMIT_AS,&limit,NULL);

    strncpy(com_proc_add.path,proc_info->path,PATH_MAX);
    com_proc_add.path[PATH_MAX] = '\0';
    com_proc_add.pid = proc_info->pid;
    if(ioctl(modfd,IOCTL_PROC_ADD,&com_proc_add)){
	return -1;
    }
    proc_info->task = com_proc_add.task;

    return 0;
}
static int judge_run(struct judge_proc_info *proc_info){
    int ret;

    struct judge_check_info *check_info;
    int waitstate;
    struct judge_com_proc_get com_proc_get;
        
    check_info = proc_info->check_info;
    if(check_info->init_fn(&check_info->private)){
	return -1;
    }

    ret = 0;

    if((proc_info->pid = fork()) == 0){
	char *argv[] = {NULL,NULL};
	char *envp[] = {NULL};

	if(check_info->run_fn(check_info->private)){
	    exit(-1);
	}
	setgid(99);
	setuid(99);
	kill(getpid(),SIGSTOP);

	argv[0] = proc_info->name;
	execve(proc_info->path,argv,envp);
    }
    if(proc_info->pid == -1){
	ret = -1;
	goto clean;
    }
    waitpid(proc_info->pid,NULL,WUNTRACED);

    if(judge_run_init(proc_info)){
	ret = -1;
	goto clean;
    }
    
    kill(proc_info->pid,SIGCONT);
    if(waitpid(proc_info->pid,&waitstate,0) == -1){
	ret = -1;
	goto clean;
    }

    com_proc_get.task = proc_info->task;
    if(ioctl(modfd,IOCTL_PROC_GET,&com_proc_get)){
	ret = -1;
	goto clean;
    }
    proc_info->runtime = com_proc_get.runtime;
    proc_info->peakmem = com_proc_get.peakmem;

    if(com_proc_get.state != JUDGE_AC){
	proc_info->state = com_proc_get.state;
    }else if(proc_info->peakmem > (proc_info->memlimit * 1024L)){
	proc_info->state = JUDGE_MLE;
    }else if(proc_info->runtime > (proc_info->timelimit * 1000L)){
	proc_info->state = JUDGE_TLE;
    }else if(!WIFEXITED(waitstate)){
	proc_info->state = JUDGE_RE;
    }else if(WEXITSTATUS(waitstate) == JUDGE_RF){
	proc_info->state = JUDGE_RF;
    }else{
	proc_info->state = check_info->post_fn(check_info->private);
    }

clean:

    if(proc_info->pid != -1){
	kill(proc_info->pid,SIGKILL);
    }
    if(proc_info->task != -1){
	ioctl(modfd,IOCTL_PROC_DEL,proc_info->task);
    }
    check_info->clean_fn(check_info->private);

    return ret;
}

int main(){
    int fd;
    FILE *f;

    setvbuf(stdout,NULL,_IONBF,0);
    freopen("log.txt","w",stdout);

    modfd = open("/dev/judge",O_RDWR);

    int i;
    for(i = 0;i < 50;i++){
	if(fork() == 0){
	    int j;
	    struct judge_proc_info *proc_info;

	    for(j = 0;j < 100;j++){
		if((proc_info = judge_init("test","/mnt/fsilter/check.so",1000,65536)) == (void*)-1){
		    printf("Error1\n");
		    continue;
		}
		if(judge_run(proc_info)){
		    printf("Error2\n");
		    continue;
		}

		printf("Time:%lu ms\n",proc_info->runtime / 1000L);
		printf("Mem:%lu KB\n",proc_info->peakmem / 1024L);
		printf("State:%d\n",proc_info->state);
	    }

	    printf("End %d\n",i);
	    exit(0);
	}
    }

    close(modfd);

    printf("End\n");
    return 0;
}
