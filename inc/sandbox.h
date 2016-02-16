#ifndef _SANDBOX_H_
#define _SANDBOX_H_

#include<vector>
#include<string>
#include<exception>
#include<unordered_map>
#include<queue>
#include<unistd.h>
#include<limits.h>
#include<sys/signal.h>
#include<libcgroup.h>

#include"utils.h"

enum sandbox_restrict_level {
    SANDBOX_RESTRICT_LOW = 0,
    SANDBOX_RESTRICT_HIGH = 1,
};
class Sandbox;
typedef void (*func_sandbox_stop_callback)(Sandbox *sdbx);

class SandboxException : public std::exception {
    private:
	std::string what_arg;

    public:
	SandboxException(const std::string &_what_arg) : what_arg(_what_arg) {
	    DBG("SandboxException: %s\n", what_arg.c_str());
	}
	virtual const char* what() const throw() {
	    return what_arg.c_str();
	}
};

class Sandbox {
    private:
	static unsigned long last_sandbox_id;
	static std::unordered_map<pid_t, Sandbox*> run_map;

	enum {
	    SANDBOX_STATE_INIT,
	    SANDBOX_STATE_PRERUN,
	    SANDBOX_STATE_RUNNING,
	    SANDBOX_STATE_STOP,
	} state;
	pid_t child_pid;
	func_sandbox_stop_callback stop_callback;

	std::string exe_path;
	std::vector<std::string> argv;
	std::vector<std::string> envp;
	std::string work_path;
	std::string root_path;
	unsigned int uid;
	unsigned int gid;
	std::vector<std::pair<unsigned int, unsigned int>> uid_map;
	std::vector<std::pair<unsigned int, unsigned int>> gid_map;
	unsigned long timelimit;
	unsigned long memlimit;
	sandbox_restrict_level restrict_level;

	struct cgroup *cg;
	struct cgroup_controller *memcg;
	uv_timer_t force_uvtimer;
	int memevt_fd;
	uv_poll_t memevt_uvpoll;

    public:
	unsigned long id;

    private:
	static void memevt_uvpoll_callback(uv_poll_t *uvpoll,
	    int status, int events);
	static void force_uvtimer_callback(uv_timer_t *uvtimer);
	static int sandbox_entry(void *data);

	int install_limit() const;
	int install_filter() const;
	void update_state(siginfo_t *siginfo);
	void stop(bool exit_error);

    public:
	static void update_sandboxes(siginfo_t *siginfo);

	Sandbox(const std::string &_exe_path,
	    const std::vector<std::string> &_argv,
	    const std::vector<std::string> &_envp,
	    const std::string &_work_path,
	    const std::string &_root_path,
	    unsigned int _uid,
	    unsigned int _gid,
	    const std::vector<std::pair<unsigned int, unsigned int>> &_uid_map,
	    const std::vector<std::pair<unsigned int, unsigned int>> &_gid_map,
	    unsigned long _timelimit,
	    unsigned long _memlimit,
	    sandbox_restrict_level _restrict_level);
	~Sandbox();
	void start(func_sandbox_stop_callback _stop_callback);
	void terminate();
};

void sandbox_init();

#endif
