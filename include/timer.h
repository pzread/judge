#ifndef _TASK_H
#define _TASK_H

#include"ev.h"

struct timer{
    int fd;
    struct ev_header evhdr;

    void (*alarm_handler)(struct timer *timer);
    void *private;
};

struct timer* timer_alloc(void);
int timer_free(struct timer *timer);
int timer_set(struct timer *timer,time_t initial,time_t interval);

#endif
