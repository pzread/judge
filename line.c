#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<dlfcn.h>
#include<limits.h>

#include"judge_def.h"
#include"judgx.h"
#include"judgx_line.h"
#include"line.h"

static void line_ini_handler(void *data,char *section,char *key,char *value){
    int i;

    struct line_setting_info *set_info;
    char *part;
    char *savpart;

    set_info = (struct line_setting_info*)data;
    if(strcmp(section,"JUDGE") == 0){
	if(strcmp(key,"timelimit") == 0){
	    set_info->timelimit = atoi(value);
	}else if(strcmp(key,"memlimit") == 0){
	    set_info->memlimit = atoi(value);
	}else if(strcmp(key,"count") == 0){
	    set_info->count = atoi(value);
	}else if(strcmp(key,"score") == 0){
	    part = strtok_r(value,",",&savpart);
	    i = 0;
	    while(part != NULL){
		set_info->score[i] = atoi(part);
		part = strtok_r(NULL,",",&savpart);
		i++;
	    }
	}
    }
}

DLL_PUBLIC int run(struct judgx_line_info *line_info){
    int i;
    
    struct line_setting_info *set_info;
    char datapath[PATH_MAX + 1];

    check_init_fn check_init;
    judgx_check_run_fn check_run;
    check_post_fn check_post;
    check_clean_fn check_clean;
    void *check_data;

    struct judgx_proc_info *proc_info;
    int status;
    int score;
    unsigned long runtime;
    unsigned long peakmem;

    printf("line1\n");

    set_info = malloc(sizeof(struct line_setting_info));
    judgx_ini_load(line_info->set_file,line_ini_handler,set_info);

    printf("line2\n");

    if(judgx_compile(line_info->cpp_path,line_info->exe_path,NULL) == JUDGE_CE){
	for(i = 0;i < set_info->count;i++){
	    line_info->result[i].status = JUDGE_CE;
	    line_info->result[i].score = 0;
	    line_info->result[i].maxscore = set_info->score[i];
	    line_info->result[i].runtime = 0;
	    line_info->result[i].peakmem = 0;
	}
	line_info->result_count = set_info->count;

	goto clean;
    }

    printf("line3\n");

    check_init = dlsym(line_info->check_dll,"init");
    check_run = dlsym(line_info->check_dll,"run");
    check_post = dlsym(line_info->check_dll,"post");
    check_clean = dlsym(line_info->check_dll,"clean");
    check_data = NULL;

    printf("line4\n");

    for(i = 0;i < set_info->count;i++){
	status = JUDGE_ERR;
	score = 0;
	runtime = 0;
	peakmem = 0;

	printf("line5\n");

	if(!(proc_info = judgx_proc_create(line_info->exe_path,set_info->timelimit,set_info->memlimit))){
	    goto proc_end;   	
	}

	printf("line7\n");

	snprintf(datapath,sizeof(datapath),"%s/%d",line_info->pro_path,(i + 1));
	if(check_init(datapath,&check_data)){
	    goto proc_clean;
	}

	if(judgx_proc_run(proc_info,check_run,check_data)){
	    goto check_clean;
	}

	if(proc_info->status == JUDGE_AC){
	    proc_info->status = check_post(check_data);
	}else if(proc_info->status == JUDGE_ERR){
	    goto check_clean;
	}

	status = proc_info->status;
	if(status == JUDGE_AC){
	    score = set_info->score[i];
	}
	runtime = proc_info->runtime;
	peakmem = proc_info->peakmem;

check_clean:

	check_clean(check_data);

proc_clean:

	judgx_proc_free(proc_info);

proc_end:

	line_info->result[i].status = status;
	line_info->result[i].score = score;
	line_info->result[i].maxscore = set_info->score[i];
	line_info->result[i].runtime = runtime;
	line_info->result[i].peakmem = peakmem;
    }

    printf("line8\n");

    line_info->result_count = set_info->count;

clean:

    free(set_info);

    printf("line10\n");

    return 0;
}
