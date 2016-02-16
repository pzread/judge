#ifndef _CORE_H_
#define _CORE_H_

#include<vector>
#include<string>
#include<uv.h>
#include"sandbox.h"

typedef void (*func_core_defer_callback)(void *data);
typedef void (*func_core_task_callback)(unsigned long id);

class Task {
    public:
	unsigned long id;
	Sandbox *sdbx;
	func_core_task_callback callback;

	Task(Sandbox *_sdbx, func_core_task_callback _callback)
	    : id(_sdbx->id), sdbx(_sdbx), callback(_callback) {}
};

int core_init();
int core_poll();
int core_defer(func_core_defer_callback callback, void *data);
unsigned long core_create_task(const std::string &exe_path,
    const std::vector<std::string> &argv,
    const std::vector<std::string> &envp,
    const std::string &work_path,
    const std::string &root_path,
    unsigned int uid,
    unsigned int gid,
    const std::vector<std::pair<unsigned int, unsigned int>> &uid_map,
    const std::vector<std::pair<unsigned int, unsigned int>> &gid_map,
    unsigned long timelimit,
    unsigned long memlimit);
int core_start_task(unsigned long id, func_core_task_callback callback);

extern uv_loop_t *core_uvloop;

#endif
