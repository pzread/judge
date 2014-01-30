#ifndef _CONTRO_H
#define _CONTRO_H

typedef void (*chal_compret_handler)(int chalid,int status);
typedef void (*chal_runret_handler)(int chalid,
	int status,unsigned long runtime,unsigned long memory);

int contro_init(void);
int chal_comp(int chalid,chal_compret_handler ret_handler,
	const char *code_path,const char *out_path);
int chal_run(int chalid,chal_runret_handler ret_handler,const char *run_path);

#endif
