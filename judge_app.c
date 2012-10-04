#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<fcntl.h>
#include<dlfcn.h>
#include<limits.h>
#include<signal.h>
#include<errno.h>
#include<pthread.h>
#include<semaphore.h>
#include<sys/ioctl.h>
#include<sys/capability.h>
#include<sys/resource.h>
#include<sys/stat.h>
#include<sys/socket.h>
#include<netinet/in.h>

#include"judge_app.h"
#include"judge_com.h"
#include"judge.h"

int main(int argc,char *argv[]){
    char cpppath[PATH_MAX + 1];
    char exepath[PATH_MAX + 1];
    int pid;
    int waitstate;
    struct judge_proc_info *proc_info;

    judge_server();

    return 0;

    snprintf(cpppath,sizeof(cpppath),"%s.cpp",argv[1]);
    strncat(exepath,argv[1],sizeof(exepath));
    
    if((pid = fork()) == 0){
	char *cpargv[] = {"g++","-O2",cpppath,"-o",exepath,NULL};
	execvp("g++",cpargv);
    }
    waitpid(pid,&waitstate,0);
    if(waitstate){
	printf("%d\n",JUDGE_CE);
	return 0;
    }

    modfd = open("/dev/judge",O_RDWR);

    close(modfd);

    return 0;
}
