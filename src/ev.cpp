#include<unordered_map>
#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<unistd.h>
#include<sys/epoll.h>

#include"ev.h"

static struct ev_data *curr_evdata;
static std::unordered_map<ev_header*, bool> unregister_ptr;

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
    unregister_ptr[evhdr] = true;
    return ev_del(curr_evdata,evhdr);
}
int ev_modify(struct ev_header *evhdr,uint32_t events){
    return ev_mod(curr_evdata,evhdr,events);
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
    int i, j;
    int evtc;
    struct epoll_event *evts = evdata->evts;
    struct ev_pollpair *polls = evdata->polls;
    struct epoll_event *evt;
    struct ev_header *evhdr;

    if((evtc = epoll_wait(evdata->epfd, evts, EVPOOL_SIZE, timeout)) < 0){
        return -1;        
    }

    unregister_ptr.clear();
    for(i = 0, j = 0;i < evtc;i++){
	evt = &evts[i];
	evhdr = (struct ev_header*)evt->data.ptr;

	if(unregister_ptr.find(evhdr) != unregister_ptr.end()) {
	    //Deleted pointer, skip it.
	    continue;
	}

	if(evhdr->handler != NULL){
	    evhdr->handler(evhdr, evt->events);
	}else{
            polls[j].fd = evhdr->fd;
            polls[j].events = evt->events;
            j++;
	}
    }

    return j;
}
int ev_close(struct ev_data *evdata){
    close(evdata->epfd);

    return 0;
}
