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
    int ret = 0;

    int srcfd = -1;
    int dstfd = -1;
    struct btrfs_ioctl_vol_args arg;

    if((srcfd = open(src,O_RDONLY | O_DIRECTORY)) < 0){
	ret = -1;
	goto end;
    }
    if((dstfd = open(dst,O_RDONLY | O_DIRECTORY)) < 0){
	ret = -1;
	goto end;
    }

    arg.fd = srcfd;
    strncpy(arg.name,name,BTRFS_PATH_NAME_MAX);
    arg.name[BTRFS_PATH_NAME_MAX] = '\0';
    if(ioctl(dstfd,BTRFS_IOC_SNAP_CREATE,&arg)){
	ret = -1;
	goto end;
    }

end:

    if(srcfd >= 0){
	close(srcfd);
    }
    if(dstfd >= 0){
	close(dstfd);
    }

    return ret;
}
int snap_delete(const char *dst,const char *name){
    int ret = 0;

    int dstfd = -1;
    struct btrfs_ioctl_vol_args arg;
    
    if((dstfd = open(dst,O_RDONLY | O_DIRECTORY)) < 0){
	ret = -1;
	goto end;
    }

    arg.fd = -1;
    strncpy(arg.name,name,BTRFS_PATH_NAME_MAX);
    arg.name[BTRFS_PATH_NAME_MAX] = '\0';
    if(ioctl(dstfd,BTRFS_IOC_SNAP_DESTROY,&arg)){
	ret = -1;
	goto end;
    }

end:

    if(dstfd >= 0){
	close(dstfd);
    }

    return ret;
}
