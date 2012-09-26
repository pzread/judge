#include<stdio.h>
#include<stdlib.h>
#include<sys/capability.h>
#include<math.h>

typedef unsigned long long ticks;

static __inline__ ticks getticks(void)
{
     unsigned a, d;
     asm("cpuid");
     asm volatile("rdtsc" : "=a" (a), "=d" (d));

     return (((ticks)a) | (((ticks)d) << 32));
}

int main(){
    /*printf("test %d\n",getpid());

    chown("/a",99,99);
    printf("%s\n",cap_to_text(cap_get_proc(),NULL));
    printf("%d %d\n",getuid(),getgid());

    printf("%d\n",fork());*/

    long long int a,b;
    /*printf("test\n");

    char buf[256];
    int p[2];
    int pa[2];

    pipe(p);
    pipe(pa);
    if((b = fork()) == 0){
	close(p[1]);
	close(pa[0]);
	write(pa[1],"1234\n",5);
	printf("    %d\n",read(p[0],buf,256));
	exit(0);
    }
    if((a = fork()) == 0){
	dup2(pa[0],0);
	dup2(p[1],1);
	close(p[0]);
	close(pa[1]);
	
	gets(buf);
	printf("abcd%s\n",buf);
	exit(0);
    }
    waitpid(a,NULL,0);*/

    int r;
    int i;

    srand(getticks());
    r = rand() % 10;

    if(r < 1){
	for(i = 0;i < 65536;i++){
	    *(long*)malloc(4096) = i;
	}
    }else if(r < 2){
	for(i = 1;i < 1000000000;i++){
	    b += ((a*i)%i)/i;
	}
    }else if(r < 4){
	fopen("ans.txt","r");
    }else if(r < 6){
	a = 0;
	*(int*)a = 100;
    }else if(r < 8){
	printf("WA\n");
    }else{
	while(scanf("%ld %ld",&a,&b) != EOF){
	    printf("%ld\n",a+b);
	}
    }

    /*srand(1009);
    for(i = 0;i < 1000000;i++){
	printf("%ld\n",rand() + rand());
    }*/

    return 0;
}
