#include<stdio.h>
#include<unistd.h>

#ifndef _UTILS_H_
#define _UTILS_H_

#define ERR(fmt,...) internal_err(LOG_PREFIX,fmt,##__VA_ARGS__)
#define INFO(fmt,...) internal_info(LOG_PREFIX,fmt,##__VA_ARGS__)
#define DBG(fmt,...) internal_dbg(LOG_PREFIX,fmt,##__VA_ARGS__)

void internal_err(const char *prefix,const char *fmt,...);
void internal_info(const char *prefix,const char *fmt,...);
void internal_dbg(const char *prefix,const char *fmt,...);

#endif
