#ifndef _CORE_H_
#define _CORE_H_

#include<string>
#include<uv.h>

extern uv_loop_t *core_uvloop;

int core_init();
int core_poll();
int core_create_task(const std::string &exepath);

#endif
