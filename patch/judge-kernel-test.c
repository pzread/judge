#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<string.h>
#include<math.h>
#include<unistd.h>
#include<signal.h>
#include<pthread.h>
#include<sys/wait.h>
#include<sys/time.h>
#include<sys/socket.h>
#include<sys/resource.h>
#include<linux/netlink.h>
#include<linux/genetlink.h>
#include<linux/taskstats.h>

#define RLIMIT_UTIME	16
#define RLIMIT_HANG	17
#undef RLIM_NLIMITS
#define RLIM_NLIMITS 18
#define NLA_DATA(x) ((char*)(x) + NLA_HDRLEN)
#define RECVBUF_SIZE 64 * 1024 * 1024

struct taskstats_ex {
    struct taskstats stats;
    uint64_t rlim_exceed[RLIM_NLIMITS];
};

static int send_msg(int fd,uint16_t nl_type,uint32_t nl_pid,
	uint8_t gl_cmd,uint16_t nla_type,void *nla_data,int nla_len);
static void handle_taskstats(void);
static int listen_task(void);

static int sockfd = -1;
static char recvbuf[RECVBUF_SIZE];

int main(void){
    pid_t lispid;
    struct rlimit rlim;
    int status;

    if((lispid = fork()) == 0){
	listen_task();
	exit(0);
    }
    




    if(fork() == 0){
	int i;

	rlim.rlim_max = 16;
	rlim.rlim_cur = rlim.rlim_max;
	setrlimit(RLIMIT_NOFILE,&rlim);

	printf("nofile test: dup %d\n",getpid());
	for(i = 0;i < 32;i++){
	    if(dup(0) == -1){
		exit(1);
	    }
	}

	exit(0);
    }
    wait(&status);
    if(WEXITSTATUS(status)){
	printf("ok\n");
    }else{
	printf("failed\n");
	goto end;
    }
    





    if(fork() == 0){
	rlim.rlim_max = 1100000;
	rlim.rlim_cur = rlim.rlim_max;
	setrlimit(RLIMIT_HANG,&rlim);

	printf("hang test: sleep %d\n",getpid());

	sleep(1);
	sleep(1);
	sleep(1);
	sleep(3);

	exit(0);
    }
    wait(&status);
    if(!WIFEXITED(status)){
	printf("ok\n");
    }else{
	printf("failed\n");
	goto end;
    }
    
    if(fork() == 0){
	int a;

	rlim.rlim_max = 1100000;
	rlim.rlim_cur = rlim.rlim_max;
	setrlimit(RLIMIT_HANG,&rlim);

	printf("hang test: read %d\n",getpid());

	printf("please don't enter anything\n");
	scanf("%d",&a);

	exit(0);
    }
    wait(&status);
    if(!WIFEXITED(status)){
	printf("ok\n");
    }else{
	printf("failed\n");
	goto end;
    }

    if(fork() == 0){
	long long int x,y,a = 23,b = 17,u;

	rlim.rlim_max = 500000;
	rlim.rlim_cur = rlim.rlim_max;
	setrlimit(RLIMIT_HANG,&rlim);

	printf("hang test: normal %d\n",getpid());

	for(x = 0;x < 2147483647;x++){
	    u = x * x * x + a * x + b;
	    y = sqrt(u);
	    if(y * y == u){
		printf("%lld %lld\n",x,y);
	    }
	}
	for(x = 0;x < 1299827;x++){
	    u = x * x * x + a * x + b;
	    printf("%lld %lf\n",x,sqrt(u));
	}

	exit(0);
    }
    wait(&status);
    if(WIFEXITED(status)){
	printf("ok\n");
    }else{
	printf("failed\n");
	goto end;
    }





    if(fork() == 0){
	rlim.rlim_max = 2500000;
	rlim.rlim_cur = rlim.rlim_max;
	setrlimit(RLIMIT_UTIME,&rlim);

	printf("utime test: while(1) %d\n",getpid());
	while(1);

	exit(0);
    }
    wait(&status);
    if(!WIFEXITED(status)){
	printf("ok\n");
    }else{
	printf("failed\n");
	goto end;
    }

end:

    kill(lispid,SIGKILL);
    wait(NULL);
    return 0;
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
static void handle_taskstats(void){
    int ret;

    struct nlmsghdr *nlhdr;
    unsigned int off;
    unsigned int len;
    struct nlattr *na;
    unsigned int aggroff;
    unsigned int aggrlen;
    struct nlattr *aggrna;

    struct taskstats_ex *statex;
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

		    statex = (struct taskstats_ex*)NLA_DATA(aggrna);
		    printf("%d %lu %lu %lu %lu\n",
			    statex->stats.ac_pid,
			    statex->rlim_exceed[RLIMIT_NPROC],
			    statex->rlim_exceed[RLIMIT_NOFILE],
			    statex->rlim_exceed[RLIMIT_UTIME],
			    statex->rlim_exceed[RLIMIT_HANG]);
		}
	    }

	    off += na->nla_len;
	    len -= na->nla_len;
	}
    }
}
static int listen_task(void){
    int ret;
    int size;
    sigset_t sigset;
    struct sockaddr_nl sa;
    struct nlmsghdr *nlhdr;
    struct nlattr *na;
    uint16_t fid;

    long cpus;
    char cpumask[64];

    sockfd = socket(AF_NETLINK,SOCK_RAW | SOCK_CLOEXEC,NETLINK_GENERIC);

    size = RECVBUF_SIZE;
    if(setsockopt(sockfd,SOL_SOCKET,SO_RCVBUF,&size,sizeof(size))){
	goto err;
    }

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

    cpus = sysconf(_SC_NPROCESSORS_CONF);
    snprintf(cpumask,64,"0-%ld",cpus - 1);

    if(send_msg(sockfd,fid,getpid(),TASKSTATS_CMD_GET,
		TASKSTATS_CMD_ATTR_REGISTER_CPUMASK,
		cpumask,strlen(cpumask) + 1)){
	goto err;
    }

    handle_taskstats();

err:

    return 0; 
}
