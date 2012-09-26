#include<stdio.h>
#include<stdlib.h>
#include<fcntl.h>
#include<signal.h>

#define JUDGE_ERR -1
#define JUDGE_AC 0
#define JUDGE_WA 1
struct check_info{
    int pin[2];
    int pout[2];

    int wpid;
    int rpid;
    int infd;
    int ansfd;
};

int init_fn(void **private){
    struct check_info *info;
    int wpid;
    int rpid;

    info = malloc(sizeof(struct check_info));
    pipe(info->pin);
    pipe(info->pout);
    info->infd = open("in.txt",O_RDONLY);
    info->ansfd = open("ans.txt",O_RDONLY);
    if(info->infd == -1 || info->ansfd == -1){
	goto error;
    }

    if((wpid = fork()) == 0){
	int ret;
	char inbuf[4096];

	close(info->pin[0]);
	while((ret = read(info->infd,inbuf,4096)) > 0){
	    write(info->pin[1],inbuf,ret);
	}
	close(info->pin[1]);
	exit(0);
    }
    close(info->pin[1]);

    if((rpid = fork()) == 0){
	int ret;
	int flag;
	char outbuf[4096];
	char ansbuf[4096];

	close(info->pout[1]);

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

	if(flag == 0){
	    exit(JUDGE_AC);
	}else{
	    exit(JUDGE_WA);
	}
    }
    close(info->pout[0]);

    if(wpid == -1 || rpid == -1){
	goto error;
    }
    info->wpid = wpid;
    info->rpid = rpid;
    *private = info;

    return 0;

error:

    kill(wpid,SIGKILL);
    kill(rpid,SIGKILL);
    close(info->pin[0]);
    close(info->pin[1]);
    close(info->pout[0]);
    close(info->pout[1]);
    close(info->infd);
    close(info->ansfd);
    free(info);

    return -1;
}
int run_fn(void *private){
    struct check_info *info;
    
    info = (struct check_info*)private;
    dup2(info->pin[0],0);
    dup2(info->pout[1],1);
    dup2(info->pout[1],2);
    close(info->pin[1]);
    close(info->pout[0]);
    
    return 0;
}
int post_fn(void *private){
    struct check_info *info;
    int state;

    info = (struct check_info*)private;
    close(info->pin[0]);
    close(info->pin[1]);
    close(info->pout[0]);
    close(info->pout[1]);

    waitpid(info->rpid,&state,0);

    return WEXITSTATUS(state);
}
int clean_fn(void *private){
    struct check_info *info;

    info = (struct check_info*)private;
    kill(info->wpid,SIGKILL);
    kill(info->rpid,SIGKILL);
    close(info->pin[0]);
    close(info->pin[1]);
    close(info->pout[0]);
    close(info->pout[1]);
    close(info->infd);
    close(info->ansfd);
    free(info);

    return 0;
}

