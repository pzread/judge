#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include"judge_ini.h"

int judge_ini_load(char *inipath,judge_ini_handler handler,void *data){
    int i;
    int j;

    FILE *f;
    char *buf;
    int l;
    char *section;
    char *key;
    char *value;

    f = fopen(inipath,"r");
    buf = malloc(1024);
    section = malloc(1024);
    key = malloc(1024);
    value = malloc(1024);

    while(fgets(buf,1024,f) != NULL){
	l = strlen(buf);
	if(buf[l - 1] == '\n'){
	    buf[l - 1] = '\0';
	}
	if(buf[0] == '\0'){
	    continue;
	}
	if(buf[0] == '['){
	    for(i = 1,j = 0;i < l && buf[i] != ']';i++,j++){
		section[j] = buf[i];
	    }
	    section[j] = '\0';
	}else{
	    for(i = 0,j = 0;i < l && buf[i] != '=';i++,j++){
		key[j] = buf[i];
	    }
	    key[j] = '\0';
	    for(i += 1,j = 0;i < l;i++,j++){
		value[j] = buf[i];
	    }
	    value[j] = '\0';
	    handler(data,section,key,value);
	}
    }

    free(buf);
    free(section);
    free(key);
    free(value);
    fclose(f);
    
    return 0;
}
