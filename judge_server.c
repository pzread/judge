#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<limits.h>
#include<pthread.h>
#include<semaphore.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<mysql/mysql.h>

#include"judge.h"
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
		i++;
	    }
	}
    }
}
static int server_compile(char *cpppath,char *exepath){
    int pid;
    int waitstate;
    
    if((pid = fork()) == 0){
	char *argv[] = {"g++","-static","-O2",cpppath,"-o",exepath,NULL};
	execvp("g++",argv);
    }
    waitpid(pid,&waitstate,0);
    if(waitstate){
	return -1;
    }

    return 0;
}
static int server_updatedb(struct judge_submit_info *submit_info,struct judge_setting_info *setting_info){
    int i;
    int j;

    char sqlstate[JUDGE_DB_STATEMAX + 1];
    char sqlscore[JUDGE_DB_SCOREMAX + 1];
    char sqlruntime[JUDGE_DB_RUNTIMEMAX + 1];
    char sqlpeakmem[JUDGE_DB_PEAKMEMMAX + 1];

    MYSQL sqli;
    char *sqlbuf;

    for(i = 0,j = 0;i < setting_info->count;i++){
	snprintf(sqlstate + j,sizeof(sqlstate) - j,"%d,",submit_info->state[i]);
	while(sqlstate[j] != '\0'){
	    j++;
	}
    }
    sqlstate[j - 1] = '\0';

    for(i = 0,j = 0;i < setting_info->count;i++){
	snprintf(sqlscore + j,sizeof(sqlscore) - j,"%d,",submit_info->score[i]);
	while(sqlscore[j] != '\0'){
	    j++;
	}
    }
    sqlscore[j - 1] = '\0';

    for(i = 0,j = 0;i < setting_info->count;i++){
	snprintf(sqlruntime + j,sizeof(sqlruntime) - j,"%lu,",submit_info->runtime[i]);
	while(sqlruntime[j] != '\0'){
	    j++;
	}
    }
    sqlruntime[j - 1] = '\0';

    for(i = 0,j = 0;i < setting_info->count;i++){
	snprintf(sqlpeakmem + j,sizeof(sqlpeakmem) - j,"%lu,",submit_info->peakmem[i]);
	while(sqlpeakmem[j] != '\0'){
	    j++;
	}
    }
    sqlpeakmem[j - 1] = '\0';
    
    mysql_init(&sqli);
    if(!mysql_real_connect(&sqli,"127.0.0.1","xxxxx","xxxxx","xxxxx",0,NULL,0)){
	return -1;
    }
    
    sqlbuf = malloc(16384);

    snprintf(sqlbuf,16384,"UPDATE submit SET state='%s',score='%s',runtime='%s',peakmem='%s' WHERE submitid='%d'",sqlstate,sqlscore,sqlruntime,sqlpeakmem,submit_info->submitid);

    mysql_real_query(&sqli,sqlbuf,strlen(sqlbuf));

    free(sqlbuf);
    mysql_close(&sqli);

    return 0;
}
static void* server_thread(void *arg){
    int i;

    struct judge_submit_info *submit_info;

    char setpath[PATH_MAX + 1];
    char cpppath[PATH_MAX + 1];
    char exepath[PATH_MAX + 1];
    char abspath[PATH_MAX + 1];
    struct judge_setting_info setting_info;
    struct judge_proc_info *proc_info;

    while(1){

	sem_wait(&server_queue_sem);

	pthread_mutex_lock(&server_queue_mutex);

	submit_info = server_queue_head.next;
	server_queue_head.next = submit_info->next;
	submit_info->next->prev = &server_queue_head;

	pthread_mutex_unlock(&server_queue_mutex);

	submit_info->submitid = 30;

	snprintf(setpath,sizeof(setpath),"%d_setting.txt",submit_info->proid);
	judge_ini_load(setpath,server_inihandler,&setting_info);

	snprintf(cpppath,sizeof(cpppath),"%d.cpp",submit_info->submitid);
	snprintf(exepath,sizeof(exepath),"%d",submit_info->submitid);

	for(i = 0;i < JUDGE_SET_COUNTMAX;i++){
	    submit_info->state[i] = JUDGE_ERR;
	    submit_info->score[i] = 0;
	    submit_info->runtime[i] = 0;
	    submit_info->peakmem[i] = 0;
	}

	if(server_compile(cpppath,exepath)){
	    for(i = 0;i < setting_info.count;i++){
		submit_info->state[i] = JUDGE_CE;
	    }
	}else{
	    for(i = 0;i < setting_info.count;i++){
		snprintf(abspath,sizeof(abspath),"%d",i + 1);

		if((proc_info = judge_proc_create(abspath,exepath,"/mnt/fsilter/check.so",setting_info.timelimit,setting_info.memlimit)) == (void*)-1){
		    submit_info->state[i] = JUDGE_ERR;
		    continue;
		}
		if(judge_proc_run(proc_info)){
		    judge_proc_free(proc_info);
		    submit_info->state[i] = JUDGE_ERR;
		    continue;
		}

		submit_info->state[i] = proc_info->state;
		if(submit_info->state[i] == JUDGE_AC){
		    submit_info->score[i] = setting_info.score[i];
		}else{
		    submit_info->score[i] = 0;
		}
		submit_info->runtime[i] = proc_info->runtime;
		submit_info->peakmem[i] = proc_info->peakmem;
		
		judge_proc_free(proc_info);
	    }
	}

	printf("%d %lu %lu\n",submit_info->state[0],submit_info->runtime[0],submit_info->peakmem[0]);
	server_updatedb(submit_info,&setting_info);

	free(submit_info);
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
    char buf[128];
    int submitid;
    int proid;
    struct judge_submit_info *submit_info;

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

    while((csd = accept(ssd,(struct sockaddr*)&saddr,&ret)) != -1){
	recv(csd,buf,128,0);
	sscanf(buf,"%d %d",&submitid,&proid);

	submit_info = malloc(sizeof(struct judge_submit_info));	
	submit_info->submitid = submitid;
	submit_info->proid = proid;

	pthread_mutex_lock(&server_queue_mutex);

	submit_info->next = &server_queue_head;
	submit_info->prev = server_queue_head.prev;
	server_queue_head.prev->next = submit_info;
	server_queue_head.prev = submit_info;

	pthread_mutex_unlock(&server_queue_mutex);

	sem_post(&server_queue_sem);
    }

    return 0;
}

