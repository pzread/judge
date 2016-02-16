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
    try {
	sandbox_init();
    } catch(SandboxException &e) {
	return -1;
    }
    task_map.clear();
    INFO("Initialized.\n");
    return 0;
}

int core_poll() {
    return uv_run(core_uvloop, UV_RUN_ONCE);
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
    task.callback(sdbx->id);

    task_map.erase(task_it);
    delete(task.sdbx);
    INFO("Task finished.\n");
}

unsigned long core_create_task(
    const std::string &exe_path,
    const std::vector<std::string> &argv,
    const std::vector<std::string> &envp,
    const std::string &work_path,
    const std::string &root_path,
    unsigned int uid,
    unsigned int gid,
    const std::vector<std::pair<unsigned int, unsigned int>> &uid_map,
    const std::vector<std::pair<unsigned int, unsigned int>> &gid_map,
    unsigned long timelimit,
    unsigned long memlimit,
    sandbox_restrict_level restrict_level
) {
    try {
	auto sdbx = new Sandbox(exe_path, argv, envp, work_path, root_path,
	    uid, gid, uid_map, gid_map, timelimit, memlimit, restrict_level);
	task_map.emplace(std::make_pair(sdbx->id, Task(sdbx, NULL)));
	return sdbx->id;
    } catch(SandboxException &e) {
	return 0;
    }
    return 0;
}

int core_start_task(unsigned long id, func_core_task_callback callback) {
    auto task_it = task_map.find(id);

    if(task_it == task_map.end()) {
	return -1;
    }
    auto &task = task_it->second;
    task.callback = callback;

    try{
	task.sdbx->start(sandbox_stop_callback);
    } catch(SandboxException &e) {
	task_map.erase(task_it);
	delete task.sdbx;
	return -1;
    }
    return 0;
}
