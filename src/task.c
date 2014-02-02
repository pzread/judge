#define _GNU_SOURCE

#define NLA_DATA(x) ((char*)(x) + NLA_HDRLEN)
#define RECVBUF_SIZE 65536
#define RECVTYPE_NLHDR 0
#define RECVTYPE_NLERR 1
#define RECVTYPE_PAYLOAD 2

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<signal.h>
#include<fcntl.h>
#include<unistd.h>
#include<sys/wait.h>
#include<sys/socket.h>
#include<sys/signalfd.h>
#include<linux/netlink.h>
#include<linux/genetlink.h>

#include"klib/khash.h"
#include"def.h"
#include"ev.h"
#include"task.h"

KHASH_MAP_INIT_INT(ptr,void*)

static int send_msg(int sd,uint16_t nl_type,uint32_t nl_pid,
	uint8_t gl_cmd,uint16_t nla_type,void *nla_data,int nla_len);
static void handle_sigchld(struct ev_header *evhdr,uint32_t events);
static void handle_taskstats(struct ev_header *evhdr,uint32_t events);

static khash_t(ptr) *task_ht = NULL;
static int sigfd = -1;
static int sockfd = -1;
static struct ev_header sigchld_evhdr;
static struct ev_header sock_evhdr;
static char recvbuf[RECVBUF_SIZE];

int task_init(void){
    int ret;

    sigset_t sigset;
    struct sockaddr_nl sa;
    struct nlmsghdr *nlhdr;
    struct nlattr *na;
    uint16_t fid;
    
    task_ht = kh_init(ptr);

    sigemptyset(&sigset);
    sigaddset(&sigset,SIGCHLD);
    sigprocmask(SIG_BLOCK,&sigset,NULL);
    if((sigfd = signalfd(-1,&sigset,SFD_NONBLOCK | SFD_CLOEXEC)) < 0){
	goto err;
    }

    sigchld_evhdr.fd = sigfd;
    sigchld_evhdr.handler = handle_sigchld;
    if(ev_register(&sigchld_evhdr,EPOLLIN | EPOLLET)){
	goto err;
    }
    
    sockfd = socket(AF_NETLINK,SOCK_RAW | SOCK_CLOEXEC,NETLINK_GENERIC);
    memset(&sa,0,sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if(bind(sockfd,(struct sockaddr*)&sa,sizeof(sa))){
	goto err;
    }

    if(send_msg(sockfd,GENL_ID_CTRL,getpid(),
		CTRL_CMD_GETFAMILY,CTRL_ATTR_FAMILY_NAME,
		TASKSTATS_GENL_NAME,strlen(TASKSTATS_GENL_NAME) + 1)){
	goto err;
    }
    if((ret = recv(sockfd,recvbuf,RECVBUF_SIZE,0)) <= 0){
	goto err;
    }
    nlhdr = (struct nlmsghdr*)recvbuf;
    if(nlhdr->nlmsg_type == NLMSG_ERROR || !NLMSG_OK(nlhdr,ret)){
	goto err;
    }
    na = (struct nlattr*)((char*)NLMSG_DATA(recvbuf) + GENL_HDRLEN);
    na = (struct nlattr*)((char*)na + NLA_ALIGN(na->nla_len));
    fid = *(uint16_t*)((char*)NLA_DATA(na));

    if(send_msg(sockfd,fid,getpid(),TASKSTATS_CMD_GET,
	    TASKSTATS_CMD_ATTR_REGISTER_CPUMASK,
	    "0-16",strlen("0-16") + 1)){
	goto err;
    }
    if(fcntl(sockfd,F_SETFL,O_NONBLOCK)){
	goto err;
    }

    sock_evhdr.fd = sockfd;
    sock_evhdr.handler = handle_taskstats;
    if(ev_register(&sock_evhdr,EPOLLIN | EPOLLET)){
	goto err;
    }

    return 0;

err:

    if(task_ht != NULL){
	kh_destroy(ptr,task_ht);
    }
    if(sigfd >= 0){
	close(sigfd);
    }
    if(sockfd >= 0){
	close(sockfd);
    }

    return -1;
}
static int send_msg(int fd,uint16_t nl_type,uint32_t nl_pid,
	uint8_t gl_cmd,uint16_t nla_type,void *nla_data,int nla_len){

    int ret;

    char buf[64];
    struct nlmsghdr *nlhdr;
    struct genlmsghdr *glhdr;
    struct nlattr *na;
    struct sockaddr_nl sa;
    unsigned int off;
    unsigned int len;
    
    nlhdr = (struct nlmsghdr*)buf;
    glhdr = (struct genlmsghdr*)NLMSG_DATA(buf);

    nlhdr->nlmsg_type = nl_type;
    nlhdr->nlmsg_flags = NLM_F_REQUEST;
    nlhdr->nlmsg_seq = 0;
    nlhdr->nlmsg_pid = nl_pid;
    glhdr->cmd = gl_cmd;
    glhdr->version = TASKSTATS_GENL_VERSION;
    na = (struct nlattr*)((char*)NLMSG_DATA(buf) + GENL_HDRLEN);
    na->nla_type = nla_type;
    na->nla_len = NLA_HDRLEN + nla_len;
    nlhdr->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN + NLA_ALIGN(na->nla_len));
    if(nlhdr->nlmsg_len > 64){
	return -1;
    }
    memcpy(((char*)NLA_DATA(na)),nla_data,nla_len);

    memset(&sa,0,sizeof(sa));
    sa.nl_family = AF_NETLINK;
    off = 0;
    len = nlhdr->nlmsg_len; 
    while((ret = sendto(fd,buf + off,len,0,
		    (struct sockaddr*)&sa,sizeof(sa))) > 0){
	off += ret;
	len -= ret;
    }

    return 0;
}
static void handle_sigchld(struct ev_header *evhdr,uint32_t events){
    int ret;

    struct signalfd_siginfo sigfd_info[4];
    siginfo_t siginfo;
    struct task *task;

    while(1){
	ret = read(sigfd,sigfd_info,sizeof(*sigfd_info) * 4);
	if(ret < (int)sizeof(struct signalfd_siginfo)){
	    break;
	}
    }
    
    while(1){
	siginfo.si_pid = 0;
	if(waitid(P_ALL,0,&siginfo,WEXITED | WSTOPPED | WCONTINUED | WNOHANG) ||
		siginfo.si_pid == 0){
	    break;
	}

	if((task = task_getby_pid(siginfo.si_pid)) == NULL){
	    continue;
	}

	if(task->sig_handler != NULL){
	    task->sig_handler(task,&siginfo);
	}
	
	task_put(task);
    }
}
static void handle_taskstats(struct ev_header *evhdr,uint32_t events){
    int ret;

    struct nlmsghdr *nlhdr;
    unsigned int off;
    unsigned int len;
    struct nlattr *na;
    unsigned int aggroff;
    unsigned int aggrlen;
    struct nlattr *aggrna;

    struct taskstats *stats;
    struct task *task;

    while((ret = recv(sockfd,recvbuf,RECVBUF_SIZE,0)) > 0){
	nlhdr = (struct nlmsghdr*)recvbuf;
	if(nlhdr->nlmsg_type == NLMSG_ERROR || !NLMSG_OK(nlhdr,ret)){
	    continue;
	}

	off = 0;
	len = NLMSG_PAYLOAD(nlhdr,0) - GENL_HDRLEN;
	while(len > 0){
	    na = (struct nlattr*)(
		    (char*)NLMSG_DATA(recvbuf + off) + GENL_HDRLEN);

	    if(na->nla_type == TASKSTATS_TYPE_AGGR_PID){
		aggroff = 0;
		aggrlen = na->nla_len - NLA_HDRLEN;
		while(aggrlen > 0){
		    aggrna = (struct nlattr*)((char*)NLA_DATA(na) + aggroff);
		    aggroff += aggrna->nla_len;
		    aggrlen -= aggrna->nla_len;

		    if(aggrna->nla_type != TASKSTATS_TYPE_STATS){
			continue;
		    }

		    stats = (struct taskstats*)NLA_DATA(aggrna);
		    if((task = task_getby_pid(stats->ac_pid)) == NULL){
			continue;
		    }

		    if(task->stat_handler != NULL){
			task->stat_handler(task,stats);
		    }
		    
		    task_put(task);
		}
	    }

	    off += na->nla_len;
	    len -= na->nla_len;
	}
    }
}

struct task* task_alloc(pid_t pid){
    int ret;

    struct task *task;
    khiter_t hit;

    if((task = malloc(sizeof(*task))) == NULL){
	return NULL;
    }

    task->refcount = 1;
    task->pid = pid;
    task->sig_handler = NULL;
    task->stat_handler = NULL;
    task->private = NULL;

    hit = kh_put(ptr,task_ht,task->pid,&ret);
    kh_value(task_ht,hit) = task;

    return task;
}
int task_get(struct task *task){
    task->refcount += 1;
    return 0;
}
int task_put(struct task *task){
    khiter_t hit;

    task->refcount -= 1; 

    if(task->refcount == 0){
        hit = kh_get(ptr,task_ht,task->pid);
        kh_del(ptr,task_ht,hit);

	free(task);
    }

    return 0;
}
struct task* task_getby_pid(pid_t pid){
    khiter_t hit;
    struct task *task;

    if((hit = kh_get(ptr,task_ht,pid)) == kh_end(task_ht)){
	return NULL;
    }

    task = kh_value(task_ht,hit);
    task_get(task);

    return task;
}
