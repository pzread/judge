typedef void (*judge_ini_handler)(void *data,char *section,char *key,char *value);

int judge_ini_load(char *inipath,judge_ini_handler handler,void *data);
