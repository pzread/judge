#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<limits.h>
#include<pthread.h>
#include<semaphore.h>
#include<sys/socket.h>
#include<netinet/in.h>

#include"judge_server.h"
#include"judge_ini.h"

static void server_inihandler(void *data,char *section,char *key,char *value){
    int i;
    
    struct judge_setting_info *setting_info;
    char *part;
    char *savpart;
    
    setting_info = (struct judge_setting_info*)data;
    if(strcmp(section,"JUDGE") == 0){
	if(strcmp(key,"timelimit") == 0){
	    setting_info->timelimit = atoi(value);
	}else if(strcmp(key,"memlimit") == 0){
	    setting_info->memlimit = atoi(value);
	}else if(strcmp(key,"count") == 0){
	    setting_info->count = atoi(value);
	}else if(strcmp(key,"score") == 0){
	    part = strtok_r(value,",",&savpart);
	    i = 0;
	    while(part != NULL){
		setting_info->score[i] = atoi(part);
		part = strtok_r(NULL,",",&savpart);
	    }
	}
    }
}
static void* server_thread(void *arg){
    int i;
    
    struct judge_server_queue *cqueue;
    int submitid;
    int proid;

    char setpath[PATH_MAX + 1];
    struct judge_setting_info setting_info;

    while(1){

	sem_wait(&server_queue_sem);

	pthread_mutex_lock(&server_queue_mutex);

	cqueue = server_queue_head.next;
	server_queue_head.next = cqueue->next;
	cqueue->next->prev = &server_queue_head;

	pthread_mutex_unlock(&server_queue_mutex);
    
	submitid = cqueue->submitid;
	proid = cqueue->proid;
	free(cqueue);

	snprintf(setpath,sizeof(setpath),"%d_setting.txt",proid);

	judge_ini_load(setpath,server_inihandler,&setting_info);

	for(i = 0;i < setting_info.count;i++){
	    
	}
    }

    return NULL;
}
int judge_server(){
    int ret;
    int i;

    pthread_t pt[4];

    int ssd;
    struct sockaddr_in saddr;
    struct sockaddr_in caddr;
    int csd;
    char *buf;
    int submitid;
    int proid;
    struct judge_server_queue *nqueue;

    server_queue_head.next = &server_queue_head;
    server_queue_head.prev = &server_queue_head;
    sem_init(&server_queue_sem,0,0);
    pthread_mutex_init(&server_queue_mutex,NULL); 

    for(i = 0;i < 4;i++){
	pthread_create(&pt[i],NULL,server_thread,NULL);
    }

    ssd = socket(AF_INET,SOCK_STREAM,0);
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(2501);
    saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(ssd,(struct sockaddr*)&saddr,sizeof(saddr));
    listen(ssd,128); 

    buf = malloc(128);
    while((csd = accept(ssd,(struct sockaddr*)&saddr,&ret)) != -1){
	recv(csd,buf,128,0);
	sscanf(buf,"%d %d",&submitid,&proid);

	nqueue = malloc(sizeof(struct judge_server_queue));	
	nqueue->submitid = submitid;
	nqueue->proid = proid;

	pthread_mutex_lock(&server_queue_mutex);
	
	nqueue->next = &server_queue_head;
	nqueue->prev = server_queue_head.prev;
	server_queue_head.prev->next = nqueue;
	server_queue_head.prev = nqueue;

	pthread_mutex_unlock(&server_queue_mutex);

	sem_post(&server_queue_sem);
    }

    return 0;
}

