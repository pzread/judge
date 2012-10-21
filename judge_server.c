#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<limits.h>
#include<pthread.h>
#include<semaphore.h>
#include<dlfcn.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<mysql/mysql.h>

#include"judge_def.h"
#include"judge.h"
#include"judgx_line.h"
#include"judge_server.h"

#define JUDGE_DB_MAXSCOREMAX 1024

static int server_updatedb(MYSQL *sqli,int submitid,int result_count,struct judgx_line_result *result){
    int i;
    int j;

    char sqlstatus[JUDGE_DB_STATUSMAX + 1];
    char sqlscore[JUDGE_DB_SCOREMAX + 1];
    int sqltotalscore;
    char sqlmaxscore[JUDGE_DB_MAXSCOREMAX + 1];
    char sqlruntime[JUDGE_DB_RUNTIMEMAX + 1];
    char sqlpeakmem[JUDGE_DB_PEAKMEMMAX + 1];

    char *sqlbuf;

    printf("sql1 %d\n",getpid());

    for(i = 0,j = 0;i < result_count;i++){
	snprintf(sqlstatus + j,sizeof(sqlstatus) - j,"%d,",result[i].status);
	while(sqlstatus[j] != '\0'){
	    j++;
	}
    }
    sqlstatus[j - 1] = '\0';

    sqltotalscore = 0;
    for(i = 0,j = 0;i < result_count;i++){
	sqltotalscore += result[i].score;
	snprintf(sqlscore + j,sizeof(sqlscore) - j,"%d,",result[i].score);
	while(sqlscore[j] != '\0'){
	    j++;
	}
    }
    sqlscore[j - 1] = '\0';

    for(i = 0,j = 0;i < result_count;i++){
	snprintf(sqlmaxscore + j,sizeof(sqlmaxscore) - j,"%d,",result[i].maxscore);
	while(sqlmaxscore[j] != '\0'){
	    j++;
	}
    }
    sqlmaxscore[j - 1] = '\0';

    for(i = 0,j = 0;i < result_count;i++){
	snprintf(sqlruntime + j,sizeof(sqlruntime) - j,"%lu,",result[i].runtime);
	while(sqlruntime[j] != '\0'){
	    j++;
	}
    }
    sqlruntime[j - 1] = '\0';

    for(i = 0,j = 0;i < result_count;i++){
	snprintf(sqlpeakmem + j,sizeof(sqlpeakmem) - j,"%lu,",result[i].peakmem);
	while(sqlpeakmem[j] != '\0'){
	    j++;
	}
    }
    sqlpeakmem[j - 1] = '\0';

    printf("sql2\n");

    sqlbuf = malloc(8192);

    snprintf(sqlbuf,8192,"UPDATE submit SET status='%s',score='%s',totalscore='%d',maxscore='%s',runtime='%s',peakmem='%s' WHERE submitid='%d'",sqlstatus,sqlscore,sqltotalscore,sqlmaxscore,sqlruntime,sqlpeakmem,submitid);
    mysql_real_query(sqli,sqlbuf,strlen(sqlbuf));

    printf("sql3\n");

    free(sqlbuf);

    printf("sql4\n");

    return 0;
}
static void* server_thread(void *arg){
    int i;

    struct judge_submit_info *submit_info;
    struct judgx_line_info *line_info;

    char tname[NAME_MAX + 1];
    char tpath[PATH_MAX + 1];

    line_run_fn line_run;

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

	line_info = malloc(sizeof(struct judgx_line_info));

	snprintf(line_info->pro_path,sizeof(line_info->pro_path),"pro/%d",submit_info->proid);
	snprintf(line_info->cpp_path,sizeof(line_info->cpp_path),"submit/%d_submit.cpp",submit_info->submitid);
	snprintf(line_info->exe_path,sizeof(line_info->exe_path),"run/%d_submit",submit_info->submitid);

	snprintf(tpath,sizeof(tpath),"pro/%d/%d_setting.txt",submit_info->proid,submit_info->proid);
	if((line_info->set_file = fopen(tpath,"r")) != NULL){

	}

	fgets(tname,sizeof(tname),line_info->set_file);
	tname[strlen(tname) - 1] = '\0';
	snprintf(tpath,sizeof(tpath),"judge/%s.so",tname);
	line_info->line_dll = dlopen(tpath,RTLD_LAZY | RTLD_NODELETE);

	fgets(tname,sizeof(tname),line_info->set_file);
	tname[strlen(tname) - 1] = '\0';
	snprintf(tpath,sizeof(tpath),"judge/%s.so",tname);
	line_info->check_dll = dlopen(tpath,RTLD_LAZY | RTLD_NODELETE);

	line_run = dlsym(line_info->line_dll,"run");
	line_run(line_info);

	server_updatedb(&sqli,submit_info->submitid,line_info->result_count,line_info->result);

	fclose(line_info->set_file);
	dlclose(line_info->line_dll);
	dlclose(line_info->check_dll);

	free(line_info);
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

	close(csd);
    }
    free(buf);

    return 0;
}

