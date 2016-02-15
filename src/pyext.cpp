#define LOG_PREFIX "pyext"

#include<cassert>
#include<csignal>
#include<queue>
#include<vector>
#include<unordered_map>
#include<pwd.h>
#include<uv.h>

#include"utils.h"
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
unsigned long create_task(
    const char *exe_path,
    const char *root_path,
    unsigned int uid,
    unsigned int gid,
    unsigned long timelimit,
    unsigned long memlimit
) {
    std::vector<std::pair<unsigned int, unsigned int>> uid_map;
    std::vector<std::pair<unsigned int, unsigned int>> gid_map;

    auto nobody_pwd = getpwnam("nobody");
    if(nobody_pwd == NULL) {
	ERR("Can't get passwd of nobody\n");
	return 0;
    }
    uid_map.emplace_back(uid, uid);
    gid_map.emplace_back(gid, gid);
    uid_map.emplace_back(0, nobody_pwd->pw_uid);
    gid_map.emplace_back(0, nobody_pwd->pw_gid);

    return core_create_task(exe_path, root_path, uid, gid, uid_map, gid_map,
	timelimit, memlimit);
}
