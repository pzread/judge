#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<unistd.h>
#include<sys/timerfd.h>
#include<sys/epoll.h>

#include"def.h"
#include"ev.h"
#include"timer.h"

static void handle_alarm(struct ev_header *evhdr,uint32_t events);

struct timer* timer_alloc(void){
    struct timer *timer = NULL;

    timer = (struct timer*)malloc(sizeof(*timer));
    timer->fd = -1;
    if((timer->fd = timerfd_create(
		    CLOCK_MONOTONIC,TFD_NONBLOCK | TFD_CLOEXEC)) < 0){
	goto err;
    }

    timer->alarm_handler = NULL;
    timer->private = NULL;

    timer->evhdr.fd = timer->fd;
    timer->evhdr.handler = handle_alarm;
    if(ev_register(&timer->evhdr,EPOLLIN)){
	goto err;
    }

    return timer;

err:

    if(timer != NULL){
	if(timer->fd >= 0){
	    close(timer->fd);
	}

	free(timer);
    }

    return NULL;
}
int timer_free(struct timer *timer){
    close(timer->fd);
    free(timer);
    return 0;
}
int timer_set(struct timer *timer,time_t initial,time_t interval){
    struct itimerspec spec;

    spec.it_value.tv_sec = initial;
    spec.it_value.tv_nsec = 0;
    spec.it_interval.tv_sec = interval;
    spec.it_interval.tv_nsec = 0;

    if(timerfd_settime(timer->fd,0,&spec,NULL)){
	return -1;
    }
    return 0;
}

static void handle_alarm(struct ev_header *evhdr,uint32_t events){
    struct timer *timer;   
    uint64_t count;

    timer = container_of(evhdr,struct timer,evhdr);
    read(timer->fd,&count,sizeof(count));

    if(timer->alarm_handler != NULL){
	timer->alarm_handler(timer);
    }
}
