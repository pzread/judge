#define _GNU_SOURCE

#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<unistd.h>
#include<sys/epoll.h>

#include"ev.h"

static struct ev_data *curr_evdata;

int ev_add(struct ev_data *evdata,struct ev_header *evhdr,uint32_t events){
    struct epoll_event evt;

    evt.events = events;
    evt.data.ptr = evhdr;

    return epoll_ctl(evdata->epfd,EPOLL_CTL_ADD,evhdr->fd,&evt);
}
int ev_del(struct ev_data *evdata,struct ev_header *evhdr){
    return epoll_ctl(evdata->epfd,EPOLL_CTL_DEL,evhdr->fd,NULL);
}
int ev_mod(struct ev_data *evdata,struct ev_header *evhdr,uint32_t events){
    struct epoll_event evt;

    evt.events = events;
    evt.data.ptr = evhdr;

    return epoll_ctl(evdata->epfd,EPOLL_CTL_MOD,evhdr->fd,&evt);
}
int ev_register(struct ev_header *evhdr,uint32_t events){
    return ev_add(curr_evdata,evhdr,events);
}
int ev_unregister(struct ev_header *evhdr){
    return ev_del(curr_evdata,evhdr);
}

int ev_init(struct ev_data *evdata){
    int epfd;

    if((epfd = epoll_create(1)) < 0){
	return -1;
    }
    evdata->epfd = epfd;

    curr_evdata = evdata;

    return 0;
}
int ev_poll(struct ev_data *evdata,int timeout){
    int i;

    int evtc;
    struct epoll_event *evts = evdata->evts;
    struct ev_pollpair *polls = evdata->polls;
    struct epoll_event *evt;
    struct ev_header *evhdr;

    if((evtc = epoll_wait(evdata->epfd,evts,EVPOOL_SIZE,timeout)) < 0){
        return -1;        
    }

    i = 0;
    for(;evtc > 0;evtc--){
	evt = &evts[evtc - 1];
	evhdr = (struct ev_header*)evt->data.ptr;

	if(evhdr->handler != NULL){
	    evhdr->handler(evhdr,evt->events);
	}else{
            polls[i].fd = evhdr->fd;
            polls[i].events = evt->events;
            i++;
	}
    }

    return i;
}
int ev_close(struct ev_data *evdata){
    close(evdata->epfd);
    free(evdata->evts);

    return 0;
}
