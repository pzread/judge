//! @file sandbox.h

//  Copyright 2016 PZ Read

//  Distributed under the MIT License.

/*

Sandbox controller header file.

*/

#ifndef INC_SANDBOX_H_
#define INC_SANDBOX_H_

#include <ev.h>
#include <utils.h>

#include <unistd.h>
#include <limits.h>
#include <sys/signal.h>
#include <libcgroup.h>
#include <vector>
#include <string>
#include <memory>
#include <utility>
#include <exception>
#include <unordered_map>
#include <queue>

class Sandbox;
enum sandbox_restrict_level {
    /*! \brief Low restriction level.

    Only isolate environment, prevent resource exhausted.

    */
    SANDBOX_RESTRICT_LOW = 0,

    /*! \brief High restriction level.

    Isolate environment, prevent resource exhausted.
    Enable user time limit, seccomp filter, strict file descriptor limit.

    */
    SANDBOX_RESTRICT_HIGH = 1,
};

/*!

Event pair for sandbox.

*/
struct sandbox_evpair {
    ev_header hdr; //!< Event ev_header.
    uint64_t id; //!< Sandbox ID.
};

/*!

Prototype of sandbox stop callback function.
 
*/
typedef void (*func_sandbox_stop_callback)(uint64_t id);

/*!

Sandbox exception.

*/
class SandboxException : public std::exception {
 private:
    std::string what_arg;

 public:
    explicit SandboxException(const std::string &_what_arg)
        : what_arg(_what_arg)
    {
        DBG("SandboxException: %s\n", what_arg.c_str());
    }
    virtual const char* what() const throw() {
        return what_arg.c_str();
    }
};

/*!

Sandbox configuration.

*/
class SandboxConfig {
 public:
    int stdin_fd; //!< Standard input file descriptor.
    int stdout_fd; //!< Standard output file descriptor.
    int stderr_fd; //!< Standard error file descriptor.
    std::string work_path; //!< Working directory in the sanbox.
    std::string root_path; //!< Root directory for chroot.
    uid_t uid; //!< UID.
    gid_t gid; //!< GID.
    std::vector<std::pair<uid_t, uid_t>> uid_map; //!< UID mapping.
    std::vector<std::pair<gid_t, gid_t>> gid_map; //!< GID mapping.
    uint64_t timelimit; //!< Timelimit.
    uint64_t memlimit; //!< Memlimit.
    sandbox_restrict_level restrict_level; //!< Restriction level.
};

/*!

Sandbox statistic.

*/
class SandboxStat {
 public:
    uint64_t utime; //!< User time (msec).
    uint64_t stime; //!< System time (msec).
    uint64_t peakmem; //!< Maximum usage of memory (bytes).
    enum {
        SANDBOX_STAT_NONE = 0, //!< No error.
        SANDBOX_STAT_OOM = 1, //!<  Memory limit exceed.
        SANDBOX_STAT_TIMEOUT = 2, //!< Time limit exceed.
        SANDBOX_STAT_FORCETIMEOUT = 3, //!< Force time limit exceed.
        SANDBOX_STAT_EXITERR = 4, //!< Runtime error.
        SANDBOX_STAT_INTERNALERR = 5, //!< Internal error.
    } detect_error; //!< Detected error.

    SandboxStat()
        : utime(0), stime(0), peakmem(0), detect_error(SANDBOX_STAT_NONE) {}
};

/*!

Sandbox class.

*/
class Sandbox : public std::enable_shared_from_this<Sandbox> {
 private:
    static uint64_t last_sandbox_id; //!< Last used Sandbox ID.
    static std::unordered_map<pid_t, std::shared_ptr<Sandbox>>
        sandbox_map; //!< Live sandboxes map
    static std::unordered_map<pid_t, uint64_t>
        run_map; //!< Prerun and running sandboxes map

    enum {
        SANDBOX_STATE_INIT, //!< Initialized.
        SANDBOX_STATE_PRERUN, //!< Wait for the process to be started.
        SANDBOX_STATE_RUNNING, //!< The process is running.
        SANDBOX_STATE_STOP, //!< The process is stopped.
    } state; //!< Process state.
    pid_t child_pid; //!< PID.
    func_sandbox_stop_callback stop_callback; //!< Sandbox stop callback.

    std::string exe_path; //!< Executable file path in the sandbox.
    std::vector<std::string> argv; //!< Arguments.
    std::vector<std::string> envp; //!< Environment variables.
    SandboxConfig config; //!< Sandbox configuration.

    cgroup *cg; //!< Cgroup.
    cgroup_controller *memcg; //!< Cgroup memory controller.
    sandbox_evpair *memevt_poll; //!< OOM event pair.
    sandbox_evpair *forcetime_poll; //!< Force timeout event pair.
    int suspend_fd; //!< Event file descriptor for process synchronization.
    int execve_count; //!< Times of execve being called.

 public:
    uint64_t id; //!< Sandbox ID.
    SandboxStat stat; //!< Sandbox statistic.

 private:
    static void memevt_handler(ev_header *hdr, uint32_t events);
    static void forcetime_handler(ev_header *hdr, uint32_t events);
    static int sandbox_entry(void *data);

    int install_limit() const;
    int install_filter() const;
    int read_stat(uint64_t *utime, uint64_t *stime, uint64_t *peakmem);
    void update_state(siginfo_t *siginfo);
    void stop(bool exit_error);

 public:
    static void update_sandboxes(siginfo_t *siginfo);

    Sandbox(const std::string &_exe_path,
        const std::vector<std::string> &_argv,
        const std::vector<std::string> &_envp,
        const SandboxConfig &_config);
    ~Sandbox() noexcept;
    // Delete unused copy and move constructors.
    Sandbox(const Sandbox &other) = delete;
    Sandbox(Sandbox &&other) noexcept = delete;
    Sandbox& operator=(const Sandbox &other) = delete;
    Sandbox& operator=(Sandbox &&other) noexcept = delete;

    void start(func_sandbox_stop_callback _stop_callback);
    void terminate();
};

void sandbox_init();

#endif // INC_SANDBOX_H_
