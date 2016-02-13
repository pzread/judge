#ifndef _CORE_H_
#define _CORE_H_

#include<uv.h>

extern uv_loop_t *core_uvloop;

int core_init();
int core_poll();

#endif
