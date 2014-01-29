#define _GNU_SOURCE

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<errno.h>
#include<fcntl.h>
#include<unistd.h>
#include<limits.h>
#include<sys/ioctl.h>
#include<linux/btrfs.h>

int snap_create(const char *src,const char *dst,const char *name){
    int srcfd;
    int dstfd;
    struct btrfs_ioctl_vol_args arg;

    if((srcfd = open(src,O_RDONLY | O_DIRECTORY)) < 0){
	return -1;
    }
    if((dstfd = open(dst,O_RDONLY | O_DIRECTORY)) < 0){
	return -1;
    }

    arg.fd = srcfd;
    strncpy(arg.name,name,BTRFS_PATH_NAME_MAX);
    arg.name[BTRFS_PATH_NAME_MAX] = '\0';
    if(ioctl(dstfd,BTRFS_IOC_SNAP_CREATE,&arg)){
	return -1;
    }

    return 0;
}
int snap_delete(const char *dst,const char *name){
    int dstfd;
    struct btrfs_ioctl_vol_args arg;
    
    if((dstfd = open(dst,O_RDONLY | O_DIRECTORY)) < 0){
	return -1;
    }

    arg.fd = -1;
    strncpy(arg.name,name,BTRFS_PATH_NAME_MAX);
    arg.name[BTRFS_PATH_NAME_MAX] = '\0';
    if(ioctl(dstfd,BTRFS_IOC_SNAP_DESTROY,&arg)){
	return -1;
    }

    return 0;
}
