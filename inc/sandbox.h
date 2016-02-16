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
#include<uv.h>

#include"utils.h"

class Sandbox;
enum sandbox_restrict_level {
    SANDBOX_RESTRICT_LOW = 0,
    SANDBOX_RESTRICT_HIGH = 1,
};
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

class SandboxConfig {
    public:
	std::string work_path;
	std::string root_path;
	unsigned int uid;
	unsigned int gid;
	std::vector<std::pair<unsigned int, unsigned int>> uid_map;
	std::vector<std::pair<unsigned int, unsigned int>> gid_map;
	unsigned long timelimit;
	unsigned long memlimit;
	sandbox_restrict_level restrict_level;
};
class SandboxStat {
    public:
	unsigned long utime;
	unsigned long stime;
	unsigned long peakmem;
	enum {
	    SANDBOX_STAT_NONE = 0,
	    SANDBOX_STAT_OOM = 1,
	    SANDBOX_STAT_TIMEOUT = 2,
	    SANDBOX_STAT_FORCETIMEOUT = 3,
	    SANDBOX_STAT_EXITERR = 4,
	    SANDBOX_STAT_INTERNALERR = 5,
	} detect_error;

	SandboxStat() : utime(0), stime(0), peakmem(0),
	    detect_error(SANDBOX_STAT_NONE) {}
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
	SandboxConfig config;

	struct cgroup *cg;
	struct cgroup_controller *memcg;
	uv_timer_t force_uvtimer;
	uv_poll_t memevt_uvpoll;
	int memevt_fd;


    public:
	unsigned long id;
	SandboxStat stat;

    private:
	static void memevt_uvpoll_callback(uv_poll_t *uvpoll,
	    int status, int events);
	static void force_uvtimer_callback(uv_timer_t *uvtimer);
	static int sandbox_entry(void *data);

	int install_limit() const;
	int install_filter() const;
	int read_stat(unsigned long *utime, unsigned long *stime,
	    unsigned long *peakmem);
	void update_state(siginfo_t *siginfo);
	void stop(bool exit_error);

    public:
	static void update_sandboxes(siginfo_t *siginfo);
	Sandbox(const std::string &_exe_path,
	    const std::vector<std::string> &_argv,
	    const std::vector<std::string> &_envp,
	    const SandboxConfig &_config);
	~Sandbox();
	void start(func_sandbox_stop_callback _stop_callback);
	void terminate();
};

void sandbox_init();

#endif
