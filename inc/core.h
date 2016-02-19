#ifndef _CORE_H_
#define _CORE_H_

#include<vector>
#include<string>
#include<memory>

#include"ev.h"
#include"sandbox.h"

typedef void (*func_core_defer_callback)(void *data);
typedef void (*func_core_task_callback)(unsigned long id,
    const SandboxStat &stat, void *data);

class Task {
    public:
	unsigned long id;
	std::shared_ptr<Sandbox> sdbx;
	func_core_task_callback callback;
	void *data;

	Task(const std::shared_ptr<Sandbox> &_sdbx,
	    func_core_task_callback _callback, void *_data
	) : id(_sdbx->id), sdbx(_sdbx), callback(_callback), data(_data) {}
};

int core_init();
unsigned long core_create_task(const std::string &exe_path,
    const std::vector<std::string> &argv,
    const std::vector<std::string> &envp,
    const SandboxConfig &config);
int core_start_task(unsigned long id,
    func_core_task_callback callback, void *data);

extern ev_data *core_evdata;

#endif
