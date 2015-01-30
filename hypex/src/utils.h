#include<stdio.h>
#include<unistd.h>
#include<string>
#include<memory>

#ifndef _UTILS_H_
#define _UTILS_H_

#define err(...) internal_err(LOG_PREFIX,##__VA_ARGS__)
#define info(...) internal_info(LOG_PREFIX,##__VA_ARGS__)

void internal_err(std::string prefix,std::string fmt,...);
void internal_info(std::string prefix,std::string fmt,...);

#endif
