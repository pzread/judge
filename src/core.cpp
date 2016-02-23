//! @file core.cpp

//  Copyright 2016 PZ Read

//  Distributed under the MIT License.

/*

Task controller, which is responsible to create, maintain, and destroy tasks.

*/

#define LOG_PREFIX "core"

#include <ev.h>
#include <utils.h>
#include <core.h>
#include <sandbox.h>

#include <cstring>
#include <cassert>
#include <cstddef>
#include <string>
#include <vector>
#include <unordered_map>
#include <queue>
#include <memory>

ev_data *core_evdata; //!< Public ev_data of event loop.
static std::unordered_map<uint64_t, Task> task_map; //!< Live tasks map.

/*!

Initialize event loop, sandbox environment, and global variables.

@return 0 if success.

*/
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

/*!

Destroy event loop.

*/
void core_destroy() {
    ev_close(core_evdata);

    INFO("Destroyed.\n");
}

/*!

Handle sandbox stop event. It will call the corresponding task stop callback,
and remove the task from task_map.

@param id Task ID.

*/
static void sandbox_stop_callback(uint64_t id) {
    auto task_it = task_map.find(id);
    assert(task_it != task_map.end());

    Task task = task_it->second;
    assert(task.callback != NULL);
    task.callback(id, task.sdbx->stat, task.data);

    task_map.erase(task_it);

    INFO("Task %lu finished.\n", id);
}

/*!

Create a task, and store the task into task_map. It won't start the task.

@param exe_path Executable file path in the sandbox.
@param argv Arguments.
@param envp Environment variables.
@param config Sandbox configuration.
@return Task ID, -1 if failed.

*/
uint64_t core_create_task(
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

/*!

Start the task.

@param id Task ID.
@param callback Task stop callback.
@param data Private data.
@return 0 if success.

*/
int core_start_task(
    uint64_t id,
    func_core_task_callback callback,
    void *data
) {
    auto task_it = task_map.find(id);

    if (task_it == task_map.end()) {
        return -1;
    }
    task_it->second.callback = callback;
    task_it->second.data = data;

    Task task = task_it->second;
    try {
        task.sdbx->start(sandbox_stop_callback);
    } catch(SandboxException &e) {
        task_map.erase(task_it);
        return -1;
    }

    INFO("Task %lu started.\n", id);
    return 0;
}
