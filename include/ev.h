#ifndef _EV_H
#define _EV_H

#define EVPOOL_SIZE 65536

#include<stdint.h>
#include<sys/epoll.h>

struct ev_pollpair{
    int fd;
    uint32_t events;
};
struct ev_data{
    int epfd;
    struct epoll_event evts[EVPOOL_SIZE];
    struct ev_pollpair polls[EVPOOL_SIZE];
};
struct ev_header{
    int fd;
    void (*handler)(struct ev_header *evhdr,uint32_t events);
};

int ev_init(struct ev_data *evdata);
int ev_add(struct ev_data *evdata,struct ev_header *evhdr,uint32_t events);
int ev_del(struct ev_data *evdata,struct ev_header *evhdr);
int ev_mod(struct ev_data *evdata,struct ev_header *evhdr,uint32_t events);
int ev_poll(struct ev_data *evdata,int timeout);
int ev_close(struct ev_data *evdata);

int ev_register(struct ev_header *evhdr,uint32_t events);
int ev_unregister(struct ev_header *evhdr);

#endif
