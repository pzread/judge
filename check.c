#include<stdio.h>
#include<stdlib.h>
#include<limits.h>
#include<fcntl.h>
#include<signal.h>
#include<pthread.h>

#define JUDGE_ERR -1
#define JUDGE_AC 0
#define JUDGE_WA 1
#define JUDGE_TLE 2
#define JUDGE_MLE 3
#define JUDGE_RF 4
#define JUDGE_RE 5
#define JUDGE_CE 6

struct check_info{
    int pin[2];
    int pout[2];

    pthread_t wpt;
    pthread_t rpt;
    int infd;
    int ansfd;
};

void* write_thread(void *arg){
    int ret;

    struct check_info *info;
    char inbuf[4096];

    info = (struct check_info*)arg;

    while((ret = read(info->infd,inbuf,10)) > 0){
	write(info->pin[1],inbuf,ret);
    }
    close(info->pin[1]);

    return NULL;
}
void* read_thread(void *arg){
    int ret;

    struct check_info *info;
    int flag;
    char outbuf[4096];
    char ansbuf[4096];

    info = (struct check_info*)arg;

    flag = 0;
    while(1){
	if((ret = read(info->pout[0],outbuf,4096)) <= 0){
	    if(read(info->ansfd,ansbuf,1) > 0){
		flag = 1;
		break;
	    }else{
		break;
	    }
	}
	if(read(info->ansfd,ansbuf,ret) != ret){
	    flag = 1;
	    break;
	}
	if(memcmp(ansbuf,outbuf,ret) != 0){
	    flag = 1;
	    break;
	}
    }
    close(info->pout[0]);

    if(flag == 0){
	return (void*)JUDGE_AC;
    }else{
	return (void*)JUDGE_WA;
    }
}

int init_fn(char *abspath,void **data){
    struct check_info *info;
    char tpath[PATH_MAX + 1];
    int wpid;
    int rpid;

    info = malloc(sizeof(struct check_info));
    pipe(info->pin);
    pipe(info->pout);
    snprintf(tpath,sizeof(tpath),"%s/in.txt",abspath);
    info->infd = open(tpath,O_RDONLY);
    snprintf(tpath,sizeof(tpath),"%s/ans.txt",abspath);
    info->ansfd = open(tpath,O_RDONLY);
    if(info->infd == -1 || info->ansfd == -1){
	goto error;
    }

    pthread_create(&info->wpt,NULL,write_thread,info);
    pthread_create(&info->rpt,NULL,read_thread,info);

    *data = info;

    return 0;

error:

    close(info->pin[0]);
    close(info->pin[1]);
    close(info->pout[0]);
    close(info->pout[1]);
    close(info->infd);
    close(info->ansfd);
    free(info);

    return -1;
}
int run_fn(void *data){
    struct check_info *info;

    info = (struct check_info*)data;
    dup2(info->pin[0],0);
    dup2(info->pout[1],1);
    dup2(info->pout[1],2);
    close(info->pin[1]);
    close(info->pout[0]);

    return 0;
}
int post_fn(void *data){
    struct check_info *info;
    void *state;

    info = (struct check_info*)data;

    close(info->pin[0]);
    close(info->pout[1]);

    pthread_join(info->wpt,NULL);
    pthread_join(info->rpt,&state);

    return (unsigned long)state;
}
int clean_fn(void *data){
    struct check_info *info;

    info = (struct check_info*)data;
    close(info->pin[0]);
    close(info->pin[1]);
    close(info->pout[0]);
    close(info->pout[1]);
    close(info->infd);
    close(info->ansfd);
    free(info);

    return 0;
}

