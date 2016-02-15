#ifndef _CORE_H_
#define _CORE_H_

#include<vector>
#include<string>
#include<uv.h>

extern uv_loop_t *core_uvloop;

int core_init();
int core_poll();
unsigned long core_create_task(const std::string &exe_path,
    const std::vector<std::string> &argv,
    const std::vector<std::string> &envp,
    const std::string &work_path,
    const std::string &root_path,
    unsigned int uid,
    unsigned int gid,
    const std::vector<std::pair<unsigned int, unsigned int>> &uid_map,
    const std::vector<std::pair<unsigned int, unsigned int>> &gid_map,
    unsigned long timelimit,
    unsigned long memlimit);

#endif
