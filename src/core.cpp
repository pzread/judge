#include<uv.h>

static uv_loop_t uvloop_instance;
uv_loop_t *core_uvloop = &uvloop_instance;

int core_init() {
    uv_loop_init(core_uvloop);   
    return 0;
}
int core_poll() {
    return uv_run(core_uvloop, UV_RUN_ONCE);
}
