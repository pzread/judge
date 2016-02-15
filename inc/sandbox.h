#ifndef _SANDBOX_H_
#define _SANDBOX_H_

#include<vector>
#include<string>
#include<exception>
#include<unordered_map>
#include<unistd.h>
#include<limits.h>
#include<sys/signal.h>
#include<libcgroup.h>

#include"utils.h"

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

	unsigned long id;
	enum {
	    SANDBOX_STATE_INIT,
	    SANDBOX_STATE_PRERUN,
	    SANDBOX_STATE_RUNNING,
	    SANDBOX_STATE_STOP,
	} state;
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
	struct cgroup *cg;
	struct cgroup_controller *memcg;
	pid_t child_pid;
	uv_timer_t force_uvtimer;

    private:
	int install_limit() const;
	int install_filter() const;
	void update_state(siginfo_t *siginfo);
	void statistic(bool exit_error);

    public:
	static void update_sandboxes(siginfo_t *siginfo);
	static void force_uvtimer_callback(uv_timer_t *uvtimer);
	static int sandbox_entry(void *data);

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
	    unsigned long _memlimit);
	~Sandbox();
	void start();
	void stop();
	void terminate();
};

void sandbox_init();

#endif
