#ifndef _SANDBOX_H_
#define _SANDBOX_H_

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
	std::string exepath;
	struct cgroup *cg;
	struct cgroup_controller *memcg;
	pid_t child_pid;

    private:
	int install_filter();
	void update_state(siginfo_t *siginfo);
	void statistic(bool exit_error);

    public:
	static void update_states(siginfo_t *siginfo);

	Sandbox(const std::string &_exepath);
	~Sandbox();
	void start();
	void terminate();
};

void sandbox_init();

#endif
