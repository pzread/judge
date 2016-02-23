//! @file utils.cpp

//  Copyright 2016 PZ Read

//  Distributed under the MIT License.

/*

Utilities and helper functions.

*/

#include <utils.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string>

/*!

Show the critical error message and hang the program.

@param prefix LOG_PREFIX.
@param fmt Format string.
@param ... Arguments.

*/
void internal_err(const char *prefix, const char *fmt, ...) {
    va_list args;
    std::string cfmt;

    cfmt = "\e[1;31m[" \
        + std::to_string(getpid()) + "][" + prefix + "]\e[m " + fmt;
    va_start(args, fmt);
    vfprintf(stderr, cfmt.c_str(), args);
    va_end(args);

    // Hang the program.
    while (1) {}
}

/*!

Show the information message.

@param prefix LOG_PREFIX.
@param fmt Format string.
@param ... Arguments.

*/
void internal_info(const char *prefix, const char *fmt, ...) {
    va_list args;
    std::string cfmt;

    cfmt = "[" + std::to_string(getpid()) + "][" + prefix + "] " + fmt;
    va_start(args, fmt);
    vfprintf(stderr, cfmt.c_str(), args);
    va_end(args);
    fflush(stderr);
}

/*!

Show the debug message.

@param prefix LOG_PREFIX.
@param fmt Format string.
@param ... Arguments.

*/
void internal_dbg(const char *prefix, const char *fmt, ...) {
    va_list args;
    std::string cfmt;

    cfmt = "\e[1;33m[" \
        + std::to_string(getpid()) + "][" + prefix + "]\e[m " + fmt;
    va_start(args, fmt);
    vfprintf(stderr, cfmt.c_str(), args);
    va_end(args);
    fflush(stderr);
}
