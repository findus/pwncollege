#include<stdlib.h>
#include<stdio.h>
#include <unistd.h>
int pwncollege() {
	return 0;
}

int main() {
	clearenv();
	int ret = pwncollege();
	int status = 0;
	int pid = fork();
	waitpid(pid,&status,0);
	char *args[] = {"nlhrekavwx","nlhrekavwx", NULL};
	execve("/challenge/embryoio_level35",args,NULL);
	return ret;
}
