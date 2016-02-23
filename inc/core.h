//! @file core.h

//  Copyright 2016 PZ Read

//  Distributed under the MIT License.

/*

Task controller header file.

*/

#ifndef INC_CORE_H_
#define INC_CORE_H_

#include <ev.h>
#include <sandbox.h>

#include <vector>
#include <string>
#include <memory>

/*!

Prototype of task callback function.

*/
typedef void (*func_core_task_callback)(uint64_t id, const SandboxStat &stat,
    void *data);

/*!

Task class. Used to maintain the task and its corresponding sandbox.

*/
class Task {
 public:
    uint64_t id; //!< Task ID.
    std::shared_ptr<Sandbox> sdbx; //!< The sandbox shared pointer.
    func_core_task_callback callback; //!< Task stop callback.
    void *data; //!< Private data of the task stop callback.

    /*!

    Constructor.
    
    @param _sdbx Sandbox shared pointer.
    @param _callback Task stop callback.
    @param _data Private data.

    */
    Task(const std::shared_ptr<Sandbox> &_sdbx,
        func_core_task_callback _callback, void *_data
    ) : id(_sdbx->id), sdbx(_sdbx), callback(_callback), data(_data) {}
};

int core_init();
void core_destroy();
uint64_t core_create_task(const std::string &exe_path,
    const std::vector<std::string> &argv,
    const std::vector<std::string> &envp,
    const SandboxConfig &config);
int core_start_task(uint64_t id, func_core_task_callback callback, void *data);

extern ev_data *core_evdata;

#endif // INC_CORE_H_
