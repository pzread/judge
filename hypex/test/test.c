#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<signal.h>

int main(){
	while(1){
		malloc(4096);
	}
	kill(getpid(),SIGSTOP);
	while(1);
	return 0;
}
