#include<stdio.h>
#include<stdarg.h>
#include<unistd.h>
#include<string>
#include"utils.h"

void internal_err(std::string prefix,std::string fmt,...) {
	va_list args;
	std::string cfmt;
	cfmt = "[" + std::to_string(getpid()) + "][" + prefix + "] " + fmt;
	va_start(args,fmt);
	vfprintf(stderr,cfmt.c_str(),args);
	va_end(args);
	while(1);
}
void internal_info(std::string prefix,std::string fmt,...) {
	va_list args;
	std::string cfmt;
	cfmt = "[" + std::to_string(getpid()) + "][" + prefix + "] " + fmt;
	va_start(args,fmt);
	vfprintf(stderr,cfmt.c_str(),args);
	va_end(args);
}
