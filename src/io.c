#define _GNU_SOURCE

#define IOBUF_SIZE 65536

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<fcntl.h>
#include<unistd.h>

#include"def.h"
#include"ev.h"
#include"io.h"

struct io_stdfile_data{
    struct io_header hdr;
    struct ev_header evhdr;
    
    int sin_fd;
    int sout_fd;
    int min_fd;
    int ans_fd;
};

static int stdfile_handle_post(struct io_header *iohdr);
static int stdfile_handle_exec(struct io_header *iohdr);
static int stdfile_handle_free(struct io_header *iohdr);
static void stdfile_check(struct ev_header *evhdr,uint32_t events);

static char inbuf[IOBUF_SIZE];
static char ansbuf[IOBUF_SIZE];

struct io_header* io_stdfile_alloc(const char *in_path,const char *ans_path){
    struct io_stdfile_data *iodata;
    int opipe[2];

    if((iodata = (struct io_stdfile_data*)malloc(sizeof(*iodata))) == NULL){
        return NULL;
    }

    iodata->hdr.post_handler = stdfile_handle_post;
    iodata->hdr.exec_handler = stdfile_handle_exec;
    iodata->hdr.free_handler = stdfile_handle_free;

    iodata->sin_fd = -1;
    iodata->sout_fd = -1;
    iodata->min_fd = -1;
    iodata->ans_fd = -1;

    if((iodata->sin_fd = open(in_path,O_RDONLY)) == -1){
	goto err;
    }
    if((iodata->ans_fd = open(ans_path,O_RDONLY)) == -1){
	goto err;
    }
    if(pipe(opipe) == -1){
	goto err;
    }
    iodata->sout_fd = opipe[1];
    iodata->min_fd = opipe[0];
    fcntl(iodata->min_fd,F_SETFL,O_NONBLOCK);
    
    iodata->evhdr.fd = iodata->min_fd;
    iodata->evhdr.handler = stdfile_check;
    ev_register(&iodata->evhdr,EPOLLIN | EPOLLET);

    return &iodata->hdr;

err:

    if(iodata->sin_fd != -1){
	close(iodata->sin_fd);
    }
    if(iodata->sout_fd != -1){
	close(iodata->sout_fd);
    }
    if(iodata->min_fd != -1){
	close(iodata->min_fd);
    }

    free(iodata);

    return NULL;
}
static int stdfile_handle_post(struct io_header *iohdr){
    struct io_stdfile_data *iodata;

    iodata = (struct io_stdfile_data*)iohdr;
    close(iodata->sin_fd);
    close(iodata->sout_fd);

    return 0;
}
static int stdfile_handle_exec(struct io_header *iohdr){
    struct io_stdfile_data *iodata;

    iodata = (struct io_stdfile_data*)iohdr;
    dup2(iodata->sin_fd,0);
    dup2(iodata->sout_fd,1);
    dup2(iodata->sout_fd,2);
    
    return 0;
}
static int stdfile_handle_free(struct io_header *iohdr){
    struct io_stdfile_data *iodata;

    iodata = (struct io_stdfile_data*)iohdr;
    free(iodata);

    return 0;
}
static void stdfile_check(struct ev_header *evhdr,uint32_t events){
    int ret;

    struct io_stdfile_data *iodata;
    int infd;
    int ansfd;
    int status = STATUS_WA;

    iodata = container_of(evhdr,struct io_stdfile_data,evhdr);
    infd = iodata->min_fd;
    ansfd = iodata->ans_fd;
    
    if(events & EPOLLIN){
	while((ret = read(infd,inbuf,IOBUF_SIZE)) > 0){
	    if(read(ansfd,ansbuf,ret) != ret || memcmp(ansbuf,inbuf,ret)){
		status = STATUS_WA;
		goto end;
	    }
	}
    }

    if(events != EPOLLIN){
	if(read(ansfd,ansbuf,1) != 0){
	    status = STATUS_WA;
	}else{
	    status = STATUS_AC;
	} 

	goto end;
    }

    return;

end:

    ev_unregister(&iodata->evhdr);
    close(iodata->min_fd);
    close(iodata->ans_fd);

    IO_END(&iodata->hdr,status);
}
