#include<stdio.h>
#include<unistd.h>
#include<signal.h>

int main(){
	kill(getpid(),SIGSTOP);
	while(1);
	return 0;
}
