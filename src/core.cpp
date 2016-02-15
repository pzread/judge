#define LOG_PREFIX "core"

#include<string>
#include<uv.h>

#include"utils.h"
#include"core.h"
#include"sandbox.h"

static uv_loop_t uvloop_instance;
uv_loop_t *core_uvloop = &uvloop_instance;

int core_init() {
    uv_loop_init(core_uvloop);   
    try {
	sandbox_init();
    } catch(SandboxException &e) {
	return -1;
    }
    INFO("Initialized.\n");
    return 0;
}

int core_poll() {
    return uv_run(core_uvloop, UV_RUN_ONCE);
}

unsigned long core_create_task(
    const std::string &exe_path,
    const std::string &root_path,
    unsigned int uid,
    unsigned int gid,
    const std::vector<std::pair<unsigned int, unsigned int>> &uid_map,
    const std::vector<std::pair<unsigned int, unsigned int>> &gid_map,
    unsigned long timelimit,
    unsigned long memlimit
) {
    try {
	auto sdbx = new Sandbox(exe_path, root_path, uid,
	    gid, uid_map, gid_map, timelimit, memlimit);
	sdbx->start();
    } catch(SandboxException &e) {
	return -1;
    }
    return 0;
}
