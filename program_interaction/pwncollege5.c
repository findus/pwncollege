#include<stdlib.h>
#include<stdio.h>
#include <unistd.h>

int pwncollege() {
	return 0;
}

int main() {
	int ret = pwncollege();
	int status = 0;
	int pid = fork();
	waitpid(pid,&status,0);
	char *args[] = {"nlhrekavwx","nlhrekavwx", NULL};
	char *envp[] =
	    {
		"dzsioq=fqenenoweh",
	    };
	execve("/challenge/embryoio_level33",args,envp);
	return ret;
}
