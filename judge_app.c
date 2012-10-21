#include<stdio.h>
#include<stdlib.h>
#include<signal.h>

#include"judge_app.h"

int main(int argc,char *argv[]){

    signal(SIGPIPE,SIG_IGN);
    judge_server();

    return 0;
}
