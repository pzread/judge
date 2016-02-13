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

int core_create_task(const std::string &exepath) {
    try {
	auto sdbx = new Sandbox(exepath);
	sdbx->start();
    } catch(SandboxException &e) {
	return -1;
    }
    return 0;
}
