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
    int waitstatus;
    
    if((pid = fork()) == 0){
	char *argv[] = {"g++","-static","-O2",cpppath,"-o",exepath,NULL};

	freopen("/dev/null","w",stdout);
	freopen("/dev/null","w",stderr);

	execvp("g++",argv);
    }
    waitpid(pid,&waitstatus,0);
    if(waitstatus){
	return -1;
    }

    return 0;
}
static int server_updatedb(MYSQL *sqli,struct judge_submit_info *submit_info,struct judge_setting_info *setting_info){
    int i;
    int j;

    char sqlstatus[JUDGE_DB_STATUSMAX + 1];
    char sqlscore[JUDGE_DB_SCOREMAX + 1];
    char sqlruntime[JUDGE_DB_RUNTIMEMAX + 1];
    char sqlpeakmem[JUDGE_DB_PEAKMEMMAX + 1];

    char *sqlbuf;

    printf("sql1 %d\n",getpid());

    for(i = 0,j = 0;i < setting_info->count;i++){
	snprintf(sqlstatus + j,sizeof(sqlstatus) - j,"%d,",submit_info->status[i]);
	while(sqlstatus[j] != '\0'){
	    j++;
	}
    }
    sqlstatus[j - 1] = '\0';

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

    printf("sql2\n");

    sqlbuf = malloc(8192);

    snprintf(sqlbuf,8192,"UPDATE submit SET status='%s',score='%s',runtime='%s',peakmem='%s' WHERE submitid='%d'",sqlstatus,sqlscore,sqlruntime,sqlpeakmem,submit_info->submitid);

    mysql_real_query(sqli,sqlbuf,strlen(sqlbuf));

    printf("sql3\n");

    free(sqlbuf);

    printf("sql4\n");

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

    MYSQL sqli;
    my_bool reconn;

    mysql_init(&sqli);
    reconn = 1;
    mysql_options(&sqli,MYSQL_OPT_RECONNECT,&reconn);
    mysql_real_connect(&sqli,"127.0.0.1","xxxxx","xxxxx","expoj",0,NULL,0);

    while(1){
	printf("in\n");

	sem_wait(&server_queue_sem);

	pthread_mutex_lock(&server_queue_mutex);

	printf("in1\n");

	submit_info = server_queue_head.next;
	server_queue_head.next = submit_info->next;
	submit_info->next->prev = &server_queue_head;

	pthread_mutex_unlock(&server_queue_mutex);

	snprintf(setpath,sizeof(setpath),"pro/%d/%d_setting.txt",submit_info->proid,submit_info->proid);
	judge_ini_load(setpath,server_inihandler,&setting_info);

	snprintf(cpppath,sizeof(cpppath),"submit/%d_submit.cpp",submit_info->submitid);
	snprintf(exepath,sizeof(exepath),"run/%d_submit",submit_info->submitid);

	for(i = 0;i < JUDGE_SET_COUNTMAX;i++){
	    submit_info->status[i] = JUDGE_ERR;
	    submit_info->score[i] = 0;
	    submit_info->runtime[i] = 0;
	    submit_info->peakmem[i] = 0;
	}

	if(server_compile(cpppath,exepath)){
	    for(i = 0;i < setting_info.count;i++){
		submit_info->status[i] = JUDGE_CE;
	    }
	}else{
	    for(i = 0;i < setting_info.count;i++){
		snprintf(abspath,sizeof(abspath),"pro/%d/%d",submit_info->proid,i + 1);

		printf("thr1\n");

		if((proc_info = judge_proc_create(abspath,exepath,"judge/check.so",setting_info.timelimit,setting_info.memlimit)) == (void*)-1){
		    submit_info->status[i] = JUDGE_ERR;
		    continue;
		}

		printf("thr2\n");

		if(judge_proc_run(proc_info)){
		    judge_proc_free(proc_info);
		    submit_info->status[i] = JUDGE_ERR;
		    continue;
		}
		submit_info->status[i] = JUDGE_ERR;

		printf("thr3\n");

		submit_info->status[i] = proc_info->status;
		if(submit_info->status[i] == JUDGE_AC){
		    submit_info->score[i] = setting_info.score[i];
		}else{
		    submit_info->score[i] = 0;
		}
		submit_info->runtime[i] = proc_info->runtime;
		submit_info->peakmem[i] = proc_info->peakmem;
		
		judge_proc_free(proc_info);
	    }
	}

	printf("%d %lu %lu\n",submit_info->status[0],submit_info->runtime[0],submit_info->peakmem[0]);
	server_updatedb(&sqli,submit_info,&setting_info);

	free(submit_info);

	printf("out\n");
    }

    mysql_close(&sqli);

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
    struct judge_submit_info *submit_info;
    
    server_queue_head.next = &server_queue_head;
    server_queue_head.prev = &server_queue_head;
    sem_init(&server_queue_sem,0,0);
    pthread_mutex_init(&server_queue_mutex,NULL); 

    for(i = 0;i < 1;i++){
	pthread_create(&pt[i],NULL,server_thread,NULL);
    }

    ssd = socket(AF_INET,SOCK_STREAM,0);
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(2501);
    saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(ssd,(struct sockaddr*)&saddr,sizeof(saddr));
    listen(ssd,128); 

    buf = malloc(65536);
    while((csd = accept(ssd,(struct sockaddr*)&saddr,&ret)) != -1){
	recv(csd,buf,65536,0);
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
    free(buf);

    return 0;
}

