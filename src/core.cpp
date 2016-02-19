#define LOG_PREFIX "core"

#include<cstring>
#include<cassert>
#include<string>
#include<unordered_map>
#include<queue>
#include<memory>

#include"ev.h"
#include"utils.h"
#include"core.h"
#include"sandbox.h"

ev_data *core_evdata;

static std::unordered_map<unsigned long, Task> task_map;

int core_init() {
    core_evdata = new ev_data();
    ev_init(core_evdata);

    task_map.clear();

    try {
	sandbox_init();
    } catch(SandboxException &e) {
	return -1;
    }

    INFO("Initialized.\n");
    return 0;
}

static void sandbox_stop_callback(unsigned long id) {
    auto task_it = task_map.find(id);
    assert(task_it != task_map.end());

    Task task = task_it->second;
    assert(task.callback != NULL);
    task.callback(id, task.sdbx->stat, task.data);

    task_map.erase(task_it);

    INFO("Task %lu finished.\n", id);
}

unsigned long core_create_task(
    const std::string &exe_path,
    const std::vector<std::string> &argv,
    const std::vector<std::string> &envp,
    const SandboxConfig &config
) {
    try {
	auto sdbx = std::make_shared<Sandbox>(exe_path, argv, envp, config);
	task_map.emplace(std::make_pair(sdbx->id, Task(sdbx, NULL, NULL)));
	return sdbx->id;
    } catch(SandboxException &e) {
	return 0;
    }
    return 0;
}

int core_start_task(
    unsigned long id,
    func_core_task_callback callback,
    void *data
) {
    auto task_it = task_map.find(id);

    if(task_it == task_map.end()) {
	return -1;
    }
    task_it->second.callback = callback;
    task_it->second.data = data;

    Task task = task_it->second;
    try{
	task.sdbx->start(sandbox_stop_callback);
    } catch(SandboxException &e) {
	task_map.erase(task_it);
	return -1;
    }

    INFO("Task %lu started.\n", id);
    return 0;
}
