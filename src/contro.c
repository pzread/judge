#define _GNU_SOURCE

#define EXEC_STACKSIZE (16 * 1024)
#define COMPILE_MEMLIMIT (256 * 1024 * 1024)
#define RUN_MEMLIMIT (256 * 1024 * 1024)

#define COMPTYPE_CLANGXX 0
#define COMPTYPE_MAKEFILE 1
#define COMPTYPE_GXX 2
#define CHALL_ST_PEND 0
#define CHALL_ST_COMP 1
#define CHALL_ST_RUN 2
#define CHALL_ST_EXIT 3

#define RLIMIT_UTIME 16
#define RLIMIT_HANG 17

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<limits.h>
#include<signal.h>
#include<sched.h>
#include<fcntl.h>
#include<unistd.h>
#include<dirent.h>
#include<semaphore.h>
#include<sys/mman.h>
#include<sys/ioctl.h>
#include<sys/resource.h>
#include<linux/btrfs.h>
#include<archive.h>
#include<archive_entry.h> 

#include"def.h"
#include"fog.h"
#include"task.h"
#include"io.h"
#include"contro.h"

struct comp_data{
    int cont_id;
    sem_t *lock;
    char out_path[PATH_MAX + 1];

    void *chal_private;
    chal_compret_handler ret_handler;
    int comp_type;
};
struct run_data{
    int cont_id;
    sem_t *lock;

    int status;
    int run_count;
    pid_t run_pid;
    struct task *task;
    struct io_header *iohdr;

    void *chal_private;
    chal_runret_handler ret_handler;

    unsigned long timelimit;
    unsigned long memlimit;
    unsigned long runtime;
    unsigned long memory;
};

static int copy_file(const char *dst,const char *src);
//static int extract_pack(const char *dst,const char *pack);
static int exec_comp(struct comp_data *cdata);
static void handle_compsig(struct task *task,siginfo_t *siginfo);
static int exec_run(struct run_data *rdata);
static void handle_runsig(struct task *task,siginfo_t *siginfo);
static void handle_runstat(struct task *task,const struct taskstats_ex *statex);
static void handle_runend(struct run_data *rdata,int status);

static int copy_file(const char *dst,const char *src){
    int ret = 0;

    int srcfd = -1;
    int dstfd = -1;

    if((srcfd = open(src,O_RDONLY | O_CLOEXEC)) < 0){
	ret = -1;
	goto end;
    }
    if((dstfd = open(dst,O_WRONLY | O_CREAT | O_CLOEXEC,0700)) < 0){
	ret = -1;
	goto end;
    }
    if(ioctl(dstfd,BTRFS_IOC_CLONE,srcfd)){
	ret = -1;
	goto end;
    }

end:

    if(srcfd >= 0){
	close(srcfd);
    }
    if(dstfd >= 0){
	close(dstfd);
    }

    return ret;
}
    
/*static int extract_pack(const char *dst,const char *pack){
    int ret = 0;

    struct archive *ar;
    struct archive_entry *entry;
    char path[PATH_MAX + 1];
    const struct stat *st;
    int fd;
    int arret;
    const void *buf;
    size_t size;
    off_t off;

    if((ar = archive_read_new()) == NULL){
	return -1;
    } 
    archive_read_support_filter_all(ar);
    archive_read_support_format_all(ar);

    if(archive_read_open_filename(ar,pack,65536)){
	archive_read_free(ar);
	return -1;
    }

    while(1){
	arret = archive_read_next_header(ar,&entry);
	if(arret == ARCHIVE_EOF){
	    break;
	}
	if(arret < ARCHIVE_WARN){
	    ret = -1;
	    goto end;
	}

	snprintf(path,PATH_MAX + 1,"%s/%s",dst,archive_entry_pathname(entry));
	st = archive_entry_stat(entry);

	if(S_ISDIR(st->st_mode)){
	    mkdir(path,0700);
	}else{
	    fd = open(path,O_WRONLY | O_CREAT | O_CLOEXEC,0700);
	    while((arret = archive_read_data_block(
			    ar,&buf,&size,&off)) != ARCHIVE_EOF){
		if(arret != ARCHIVE_OK){
		    close(fd);
		    ret = -1;
		    goto end;
		}

		write(fd,buf,size);    
	    }
	    close(fd);
	}
    }
    
end:

    archive_read_close(ar);
    archive_read_free(ar);
    
    return ret;

}*/

int chal_comp(chal_compret_handler ret_handler,void *chalpri,int comp_type,
        const char *res_path,const char *code_path,const char *out_path){

    struct comp_data *cdata = NULL;
    int contid = -1; 
    char path[PATH_MAX + 1];
    void *stack = NULL;
    pid_t pid = 0;
    struct task *task = NULL;

    if((cdata = malloc(sizeof(*cdata))) == NULL){
	goto err; 
    }
    cdata->chal_private = chalpri;
    cdata->ret_handler = ret_handler;
    cdata->comp_type = comp_type;

    if((cdata->lock = mmap(NULL,sizeof(*cdata->lock),PROT_READ | PROT_WRITE,
		    MAP_SHARED | MAP_ANONYMOUS,-1,0)) == NULL){
        goto err;
    }
    sem_init(cdata->lock,1,0);

    if((contid = fog_cont_alloc("compile")) < 0){
        goto err;
    }
    if(fog_cont_set(contid,COMPILE_MEMLIMIT)){
	goto err;
    }
    cdata->cont_id = contid;

    snprintf(path,PATH_MAX + 1,"container/%d/code/main.cpp",contid);
    if(copy_file(path,code_path)){
	goto err;
    }
    chown(path,FOG_CONT_UID,FOG_CONT_GID);

    if(comp_type == COMPTYPE_MAKEFILE){
        DIR *dirp;
        struct dirent *entry;
        char src[PATH_MAX + 1];
        char dst[PATH_MAX + 1];

        snprintf(path,PATH_MAX + 1,"%s/make",res_path);
        if((dirp = opendir(path)) == NULL){
	    goto err;
	}

        while((entry = readdir(dirp)) != NULL){
	    if(!strcmp(entry->d_name,".") || !strcmp(entry->d_name,"..")){
                continue;
            }

            snprintf(src,PATH_MAX + 1,"%s/make/%s",res_path,entry->d_name);
            snprintf(dst,PATH_MAX + 1,"container/%d/code/%s",
                    contid,entry->d_name);
            copy_file(dst,src);
            chown(dst,FOG_CONT_UID,FOG_CONT_GID);
        }

        closedir(dirp);
    }

    strncpy(cdata->out_path,out_path,PATH_MAX);
    cdata->out_path[PATH_MAX] = '\0';

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
    
    if(task != NULL){
        task_put(task);
    }
    if(pid > 0){
        kill(pid,SIGKILL);
    }
    if(stack != NULL){
        munmap(stack,EXEC_STACKSIZE);
    }
    if(contid != -1){
        fog_cont_free(contid);
    }
    if(cdata != NULL){
	if(cdata->lock != NULL){
	    sem_destroy(cdata->lock);
	    munmap(cdata->lock,sizeof(*cdata->lock));
	}

	free(cdata);
    }
    
    return -1;
}
static int exec_comp(struct comp_data *cdata){
    int nullfd;

    char *clangxx_args[] = {"clang++","-O2","-std=c++1y",
        "/code/main.cpp","-o","/out/a.out","-q",NULL};
    char *clangxx_envp[] = {"PATH=/usr/bin",NULL};

    char *make_args[] = {"make",NULL};
    char *make_envp[] = {"PATH=/usr/bin","OUT=/out/a.out",NULL};

    char *gxx_args[] = {"g++","-O2","-std=c++1y",
        "/code/main.cpp","-o","/out/a.out",NULL};
    char *gxx_envp[] = {"PATH=/usr/bin",NULL};

    sem_wait(cdata->lock);

    nullfd = open("/dev/null",O_WRONLY);
    
    if(fog_cont_attach(cdata->cont_id)){
        exit(1);
    }
    /*if(extract_pack("/code","/pack.tar.xz")){
	exit(1);
    }*/

    dup2(nullfd,1);
    dup2(nullfd,2);

    switch(cdata->comp_type){
        case COMPTYPE_CLANGXX:
            execve("/usr/bin/clang++",clangxx_args,clangxx_envp);
            break;

        case COMPTYPE_MAKEFILE:
            chdir("/code");
            execve("/usr/bin/make",make_args,make_envp);
            break;

        case COMPTYPE_GXX:
            execve("/usr/bin/g++",gxx_args,gxx_envp);
            break;

        default:
            exit(1);
    }
    return 0;
}
static void handle_compsig(struct task *task,siginfo_t *siginfo){
    struct comp_data *cdata;
    char path[PATH_MAX + 1];

    if(siginfo->si_code != CLD_EXITED &&
	    siginfo->si_code != CLD_KILLED &&
	    siginfo->si_code != CLD_DUMPED){

	kill(task->pid,SIGKILL); 
	return;
    }

    cdata = (struct comp_data*)task->private;
    if(siginfo->si_code != CLD_EXITED || siginfo->si_status != 0){
	cdata->ret_handler(cdata->chal_private,STATUS_CE);
    }else{
	snprintf(path,PATH_MAX + 1,"container/%d/out/a.out",cdata->cont_id);
	copy_file(cdata->out_path,path);
	cdata->ret_handler(cdata->chal_private,STATUS_NONE);
    }

    task_put(task);
    fog_cont_free(cdata->cont_id);
    sem_destroy(cdata->lock);
    munmap(cdata->lock,sizeof(*cdata->lock));
    free(cdata);
}
int chal_run(chal_runret_handler ret_handler,void* chalpri,
	const char *run_path,unsigned long timelimit,unsigned long memlimit,
        const char *in_path,const char *ans_path){
    struct run_data *rdata = NULL;
    struct io_header *iohdr = NULL;
    int contid = -1; 
    char path[PATH_MAX + 1];
    void *stack = NULL;
    pid_t pid = 0;
    struct task *task = NULL;
    
    if((rdata = malloc(sizeof(*rdata))) == NULL){
	goto err; 
    }
    rdata->chal_private = chalpri;
    rdata->ret_handler = ret_handler;

    if((rdata->lock = mmap(NULL,sizeof(*rdata->lock),PROT_READ | PROT_WRITE,
		    MAP_SHARED | MAP_ANONYMOUS,-1,0)) == NULL){
        goto err;
    }

    sem_init(rdata->lock,1,0);

    if((contid = fog_cont_alloc("run")) < 0){
        goto err;
    }
    if(fog_cont_set(contid,RUN_MEMLIMIT)){
	goto err;
    }
    rdata->cont_id = contid;
    rdata->timelimit = timelimit;
    rdata->memlimit = memlimit;

    snprintf(path,PATH_MAX + 1,"container/%d/run/a.out",contid);
    if(copy_file(path,run_path)){
	goto err;
    }
    chown(path,FOG_CONT_UID,FOG_CONT_GID);

    if((iohdr = io_stdfile_alloc(in_path,ans_path)) == NULL){
	goto err;
    }
    iohdr->end_data = rdata;
    iohdr->end_handler = (void (*)(void*,int))handle_runend;
    rdata->iohdr = iohdr;

    if((stack = mmap(NULL,EXEC_STACKSIZE,PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,-1,0)) == NULL){
        goto err;
    }
    if((pid = clone((int (*)(void*))exec_run,stack + EXEC_STACKSIZE,
		    SIGCHLD | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWNS |
		    CLONE_NEWUTS,rdata)) < 0){
        goto err;
    }
    munmap(stack,EXEC_STACKSIZE);

    if((task = task_alloc(pid)) == NULL){
        goto err;
    }
    task->private = rdata;
    task->sig_handler = handle_runsig;
    task->stat_handler = handle_runstat;

    rdata->status = STATUS_NONE;
    rdata->run_count = 2;
    rdata->run_pid = pid;
    rdata->task = task;
    
    if(IO_POST(iohdr)){
	goto err;
    }

    sem_post(rdata->lock);

    return 0;

err:

    if(task != NULL){
        task_put(task);
    }
    if(pid > 0){
        kill(pid,SIGKILL);
    }
    if(iohdr != NULL){
	IO_FREE(iohdr);
    }
    if(stack != NULL){
        munmap(stack,EXEC_STACKSIZE);
    }
    if(contid != -1){
	fog_cont_free(contid);
    }
    if(rdata != NULL){
	if(rdata->lock != NULL){
	    sem_destroy(rdata->lock);
	    munmap(rdata->lock,sizeof(*rdata->lock));
	}

	free(rdata);
    }

    return -1;
}
static int exec_run(struct run_data *rdata){
    DIR *dirp;
    int expfd;
    struct dirent *entry;
    long int fd;

    struct rlimit limit;
    char *args[] = {"a.out",NULL};
    char *envp[] = {NULL};
    
    sem_wait(rdata->lock);

    if(IO_EXEC(rdata->iohdr)){
	exit(1); 
    }

    if((dirp = opendir("/proc/self/fd")) == NULL){
	exit(1); 
    }
    expfd = dirfd(dirp);

    while((entry = readdir(dirp)) != NULL){
        if(!strcmp(entry->d_name,".") || !strcmp(entry->d_name,"..")){
            continue;
        }
        
        fd = strtol(entry->d_name,NULL,10);
        if(fd == LONG_MAX || fd == LONG_MIN){
            closedir(dirp);
            exit(1);
        }

        if(fd > 2 && fd != (long int)expfd){
            if(close((int)fd)){
                closedir(dirp);
                exit(1);
            }
        }
    }
    closedir(dirp);

    if(fog_cont_attach(rdata->cont_id)){
        exit(1);
    }
    
    limit.rlim_cur = 16;
    limit.rlim_max = limit.rlim_cur;
    setrlimit(RLIMIT_NOFILE,&limit);
    limit.rlim_cur = (rdata->timelimit + 100UL) * 1000UL;
    limit.rlim_max = limit.rlim_cur;
    setrlimit(RLIMIT_UTIME,&limit);
    limit.rlim_cur = 1000000UL;
    limit.rlim_max = limit.rlim_cur;
    setrlimit(RLIMIT_HANG,&limit);
    limit.rlim_cur = rdata->memlimit + 65536UL;
    limit.rlim_max = limit.rlim_cur;
    setrlimit(RLIMIT_AS,&limit);

    execve("/run/a.out",args,envp);
    return 0;
}
static void handle_runsig(struct task *task,siginfo_t *siginfo){
    struct run_data *rdata;

    rdata = (struct run_data*)task->private;

    if(siginfo->si_code != CLD_EXITED &&
	    siginfo->si_code != CLD_KILLED &&
	    siginfo->si_code != CLD_DUMPED){

	kill(task->pid,SIGKILL); 
    }else{
	rdata->run_pid = 0;
	task->sig_handler = NULL;
    }

    if(siginfo->si_code != CLD_EXITED){
	rdata->status = max(rdata->status,STATUS_RE);
    }
}
static void handle_runstat(struct task *task,const struct taskstats_ex *statex){
    struct run_data *rdata;
    int status = STATUS_NONE;

    rdata = (struct run_data*)task->private;
    rdata->run_pid = 0;
    task->stat_handler = NULL;
    rdata->runtime = statex->stats.ac_utime / 1000UL;
    rdata->memory = statex->stats.hiwater_vm * 1024UL;

    if(rdata->memory > rdata->memlimit){
	status = STATUS_MLE;
    }else if(statex->rlim_exceed[RLIMIT_AS] > 0){
	rdata->memory = rdata->memlimit;
	status = STATUS_MLE;
    }else if(statex->stats.ac_utime > rdata->timelimit * 1000UL){
	status = STATUS_TLE;
    }else if(statex->rlim_exceed[RLIMIT_HANG] > 0){
	status = STATUS_TLE;
    }

    handle_runend(rdata,status);
}
static void handle_runend(struct run_data *rdata,int status){
    if(rdata->run_pid != 0){
	kill(rdata->run_pid,SIGKILL);
    }

    rdata->status = max(rdata->status,status);

    rdata->run_count -= 1;
    if(rdata->run_count == 0){
	rdata->ret_handler(rdata->chal_private,
		rdata->status,rdata->runtime,rdata->memory);

	IO_FREE(rdata->iohdr);
	if(fog_cont_free(rdata->cont_id)){
            printf("fog cont free failed\n");
        }
	sem_destroy(rdata->lock);
	munmap(rdata->lock,sizeof(*rdata->lock));
	free(rdata);
    }
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
