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

#include"judge_def.h"
#include"judgx.h"
#include"judgx_com.h"
#include"judgx_lib.h"

static __attribute__((constructor)) void judgx_init(){
    judgx_modfd = open("/dev/judgm",O_RDWR);
    return;
}
static __attribute__((destructor)) void judgx_exit(){
    close(judgx_modfd);
    return;
}

DLL_PUBLIC int judgx_ini_load(FILE *f,judgx_ini_handler handler,void *data){
    int i;
    int j;

    char *buf;
    int l;
    char *section;
    char *key;
    char *value;

    buf = malloc(1024);
    section = malloc(1024);
    key = malloc(1024);
    value = malloc(1024);

    while(fgets(buf,1024,f) != NULL){
	l = strlen(buf);
	if(buf[l - 1] == '\n'){
	    buf[l - 1] = '\0';
	}
	if(buf[0] == '\0'){
	    continue;
	}
	if(buf[0] == '['){
	    for(i = 1,j = 0;i < l && buf[i] != ']';i++,j++){
		section[j] = buf[i];
	    }
	    section[j] = '\0';
	}else{
	    for(i = 0,j = 0;i < l && buf[i] != '=';i++,j++){
		key[j] = buf[i];
	    }
	    key[j] = '\0';
	    for(i += 1,j = 0;i < l;i++,j++){
		value[j] = buf[i];
	    }
	    value[j] = '\0';
	    handler(data,section,key,value);
	}
    }

    free(buf);
    free(section);
    free(key);
    free(value);
    
    return 0;
}

DLL_PUBLIC int judgx_compile(char *cpppath,char *exepath,char *arg){
    int pid;
    int waitstatus;
    
    if((pid = fork()) == 0){
	char *argv[] = {"g++","-static","-O2",cpppath,"-lrt","-o",exepath,NULL};

	freopen("/dev/null","w",stdout);
	freopen("/dev/null","w",stderr);

	execvp("g++",argv);
    }
    waitpid(pid,&waitstatus,0);
    if(waitstatus){
	return JUDGE_CE;
    }
    return 0;
}


DLL_PUBLIC struct judgx_proc_info* judgx_proc_create(char *exepath,unsigned long timelimit,unsigned long memlimit){
    int ret;
    int i,j;

    struct stat st;
    struct judgx_proc_info *proc_info;

    if(stat(exepath,&st)){
	return (void*)-1;
    }
    if(!S_ISREG(st.st_mode)){
	return (void*)-1;
    }

    proc_info = malloc(sizeof(struct judgx_proc_info));
    if(proc_info == NULL){
	goto error;
    }

    proc_info->exe_path[0] = '\0';
    strncat(proc_info->exe_path,exepath,sizeof(proc_info->exe_path));

    proc_info->exe_name[NAME_MAX] = '\0';
    for(i = 0,j = 0;proc_info->exe_path[i] != '\0' && j < NAME_MAX;i++){
	if(proc_info->exe_path[i] == '/'){
	    j = 0;
	}else{
	    proc_info->exe_name[j] = proc_info->exe_path[i];
	    j++;
	}
    }
    proc_info->status = JUDGE_ERR;
    proc_info->exe_name[j] = '\0';
    proc_info->pid = -1;
    proc_info->task = -1;
    proc_info->timelimit = timelimit;
    proc_info->memlimit = memlimit;
    proc_info->runtime = 0L;
    proc_info->peakmem = 0L;

    return proc_info;

error:

    if(proc_info != NULL){
	free(proc_info);
    }

    return NULL;
}
DLL_PUBLIC int judgx_proc_free(struct judgx_proc_info *proc_info){
    free(proc_info);
    return 0;
}
static int proc_protect(struct judgx_proc_info *proc_info){
    cap_t caps;
    struct rlimit limit;
    struct judgx_com_proc_add com_proc_add;

    /*caps = cap_init();
    if(cap_set_file(proc_info->path,caps)){
	cap_free(caps);
	goto error;
    }
    cap_free(caps);*/

    limit.rlim_cur = 1;
    limit.rlim_max = limit.rlim_cur;
    prlimit(proc_info->pid,RLIMIT_NPROC,&limit,NULL);

    limit.rlim_cur = 4L;
    limit.rlim_max = limit.rlim_cur;
    prlimit(proc_info->pid,RLIMIT_NOFILE,&limit,NULL);

    limit.rlim_cur = (proc_info->timelimit) / 1000L + 1L;
    limit.rlim_max = limit.rlim_cur;
    prlimit(proc_info->pid,RLIMIT_CPU,&limit,NULL);

    /*limit.rlim_cur = proc_info->memlimit * 1024L + 4096L * 128L;
    limit.rlim_max = limit.rlim_cur;
    prlimit(proc_info->pid,RLIMIT_AS,&limit,NULL);*/

    com_proc_add.path[0] = '\0';
    strncat(com_proc_add.path,proc_info->exe_path,sizeof(com_proc_add.path));
    com_proc_add.pid = proc_info->pid;
    com_proc_add.memlimit = proc_info->memlimit * 1024L + 4096L * 128L;
    if(ioctl(judgx_modfd,IOCTL_PROC_ADD,&com_proc_add)){
	return -1;
    }
    proc_info->task = com_proc_add.task;

    return 0;
}
DLL_PUBLIC int judgx_proc_run(struct judgx_proc_info *proc_info,judgx_check_run_fn check_run,void *check_data){
    int ret;

    int waitstatus;
    struct judgx_com_proc_get com_proc_get;
        
    ret = 0;

    printf("proc1\n");

    if((proc_info->pid = fork()) == 0){
	char *argv[] = {NULL,NULL};
	char *envp[] = {NULL};

	check_run(check_data);

	setgid(99);
	setuid(99);
	kill(getpid(),SIGSTOP);

	argv[0] = proc_info->exe_name;
	execve(proc_info->exe_path,argv,envp);
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
    if(ioctl(judgx_modfd,IOCTL_PROC_GET,&com_proc_get)){
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
	proc_info->status = JUDGE_AC;
    }

    printf("proc6\n");

clean:

    if(proc_info->pid != -1){
	kill(proc_info->pid,SIGKILL);
    }
    if(proc_info->task != -1){
	ioctl(judgx_modfd,IOCTL_PROC_DEL,proc_info->task);
    }

    printf("proc7\n");

    return ret;
}

