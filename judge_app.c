#include<stdio.h>
#include<stdlib.h>
#include<fcntl.h>
#include<signal.h>

#include"judge_app.h"

int main(int argc,char *argv[]){

    signal(SIGPIPE,SIG_IGN);

    judge_modfd = open("/dev/judgm",O_RDWR);
    judge_server();
    close(judge_modfd);

    return 0;
}
