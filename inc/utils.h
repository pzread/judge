//! @file utils.h

//  Copyright 2016 PZ Read

//  Distributed under the MIT License.

/*

Utils header file.

*/

#include <stdio.h>
#include <unistd.h>

#ifndef INC_UTILS_H_
#define INC_UTILS_H_

#ifndef LOG_PREFIX
#define LOG_PREFIX "unknown"
#endif

#define ERR(fmt, ...) internal_err(LOG_PREFIX, fmt, ##__VA_ARGS__)
#define INFO(fmt, ...) internal_info(LOG_PREFIX, fmt, ##__VA_ARGS__)
#define DBG(fmt, ...) internal_dbg(LOG_PREFIX, fmt, ##__VA_ARGS__)

void internal_err(const char *prefix, const char *fmt, ...);
void internal_info(const char *prefix, const char *fmt, ...);
void internal_dbg(const char *prefix, const char *fmt, ...);

#endif // INC_UTILS_H_
