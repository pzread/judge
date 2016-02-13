#include<cassert>
#include<csignal>
#include<queue>
#include<unordered_map>
#include<uv.h>

#include"core.h"

struct eventpair {
    int fd;
    int events;
};

static uv_timer_t poll_uvtimer;
static std::unordered_map<int, uv_poll_t*> poll_map;
static std::queue<std::pair<int, int>> pend_events;

static void uvpoll_callback(uv_poll_t *uvpoll, int status, int events) {
    int fd;

    uv_fileno((uv_handle_t*)uvpoll, &fd);
    if(status == 0) {
	pend_events.emplace(fd, events);
    } else {
	pend_events.emplace(fd, status);
    }
}
static void dummy_uvtimer_callback(uv_timer_t *uvtimer) {}

extern "C" __attribute__((visibility("default"))) int init() {
    if(core_init()) {
	return -1;
    }
    poll_map.clear();
    while(!pend_events.empty()) {
	pend_events.pop();
    }
    uv_timer_init(core_uvloop, &poll_uvtimer);
    return 0;
}

extern "C" __attribute__((visibility("default")))
int ev_register(int fd, int events) {
    assert(poll_map.find(fd) == poll_map.end());

    auto uvpoll = new uv_poll_t;
    uv_poll_init(core_uvloop, uvpoll, fd);
    poll_map[fd] = uvpoll;
    uv_poll_start(uvpoll, events, uvpoll_callback);
    return 0;
}
extern "C" __attribute__((visibility("default")))
int ev_unregister(int fd) {
    assert(poll_map.find(fd) != poll_map.end());

    auto uvpoll = poll_map[fd];
    uv_poll_stop(uvpoll);
    poll_map.erase(fd);
    delete uvpoll;
    return 0;
}
extern "C" __attribute__((visibility("default")))
int ev_modify(int fd, int events) {
    assert(poll_map.find(fd) != poll_map.end());

    uv_poll_start(poll_map[fd], events, uvpoll_callback);
    return 0;
}
extern "C" __attribute__((visibility("default")))
int ev_poll(long timeout, eventpair ret[], int maxevts) {
    int i;

    uv_timer_start(&poll_uvtimer, dummy_uvtimer_callback, timeout, 0);
    core_poll();
    uv_timer_stop(&poll_uvtimer);

    i = 0;
    while(!pend_events.empty()) {
	if(i >= maxevts) {
	    break;
	}
	auto evt = pend_events.front();
	pend_events.pop();

	ret[i].fd = evt.first;
	ret[i].events = evt.second;
	i += 1;
    }
    return i;
}

extern "C" __attribute__((visibility("default")))
int create_task(const char *exepath) {
    return core_create_task(exepath);
}
