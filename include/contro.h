#ifndef _CONTRO_H
#define _CONTRO_H

typedef void (*chal_compret_handler)(void *chalpri,int status);
typedef void (*chal_runret_handler)(void *chalpri,
	int status,unsigned long runtime,unsigned long memory);

int contro_init(void);
int chal_comp(chal_compret_handler ret_handler,void *chalpri,int comp_type,
        const char *res_path,const char *code_path,const char *out_path);
int chal_run(chal_runret_handler ret_handler,void* chalpri,
	const char *run_path,unsigned long timelimit,unsigned long memlimit,
        const char *in_path,const char *ans_path);

#endif
