#define LOG_PREFIX "core"

#include<cassert>
#include<string>
#include<unordered_map>
#include<queue>
#include<uv.h>

#include"utils.h"
#include"core.h"
#include"sandbox.h"

static uv_loop_t uvloop_instance;
uv_loop_t *core_uvloop = &uvloop_instance;

static uv_timer_t defer_uvtimer;
static std::queue<std::pair<func_core_defer_callback, void*>> defer_queue;
static std::unordered_map<unsigned long, Task> task_map;

static void defer_uvtimer_callback(uv_timer_t *uvtimer) {
    while(!defer_queue.empty()) {
	auto defer = defer_queue.front();
	defer_queue.pop();
	defer.first(defer.second);
    }
}

int core_init() {
    uv_loop_init(core_uvloop);   
    uv_timer_init(core_uvloop, &defer_uvtimer);
    task_map.clear();

    try {
	sandbox_init();
    } catch(SandboxException &e) {
	return -1;
    }

    INFO("Initialized.\n");
    return 0;
}

int core_poll(bool nowait) {
    if(nowait) {
	return uv_run(core_uvloop, UV_RUN_NOWAIT);
    } else {
	return uv_run(core_uvloop, UV_RUN_ONCE);
    }
}

int core_defer(func_core_defer_callback callback, void *data) {
    defer_queue.emplace(callback, data);
    uv_timer_start(&defer_uvtimer, defer_uvtimer_callback, 0, 0);
    return 0;
}

static void sandbox_stop_callback(Sandbox *sdbx) {
    auto task_it = task_map.find(sdbx->id);
    assert(task_it != task_map.end());

    auto &task = task_it->second;
    assert(task.callback != NULL);
    task.callback(sdbx->id, sdbx->stat, task.data);

    task_map.erase(task_it);
    delete(task.sdbx);

    INFO("Task finished.\n");
}

unsigned long core_create_task(
    const std::string &exe_path,
    const std::vector<std::string> &argv,
    const std::vector<std::string> &envp,
    const SandboxConfig &config
) {
    try {
	auto sdbx = new Sandbox(exe_path, argv, envp, config);
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
    auto &task = task_it->second;
    task.callback = callback;
    task.data = data;

    try{
	task.sdbx->start(sandbox_stop_callback);
    } catch(SandboxException &e) {
	task_map.erase(task_it);
	delete task.sdbx;
	return -1;
    }
    return 0;
}
