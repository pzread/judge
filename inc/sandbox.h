#ifndef _SANDBOX_H_
#define _SANDBOX_H_

#include<unistd.h>
#include<limits.h>
#include<libcgroup.h>
#include<string>
#include<exception>

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
	std::string exepath;
	struct cgroup *cg;
	struct cgroup_controller *memcg;
	pid_t child_pid;

    public:
	Sandbox(const std::string &_exepath);
	void start();
};

void sandbox_init();
unsigned long sandbox_create();

#endif
