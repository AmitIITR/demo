/* Filename: docker_run.c
 * This code is written to modify docker run  command line arguments and 
 * hooking inception java agent.
 *
 * Assumption: docker run is started with sudo. You need to modify code to handle
 * the case where docker can be run without sudo.
 * 
 * Example:
 * origional command: sudo docker run -it --privileged --rm  --name jdk_1 openjdk bash 
 *
 * modified by command: sudo docker run -it --privileged --rm --env LD_PRELOAD=/opt/exec.so -v /home/ec2-user/ldp_demo/execve_so:/opt --name jdk_1 openjdk bash 
 *
 * compile command: gcc -std=c99 -o docker_run.so -shared docker_run.c -Wall -Wfatal-errors -fPIC -g -ldl 
 *
 */

#define _GNU_SOURCE
#include <unistd.h>
#include<fcntl.h> 
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

//Input command is sudo docker run -it --privileged --rm  --name jdk_1 openjdk bash
typedef ssize_t (*execve_func_t)(const char* filename, char* const argv[], char* const envp[]);
static execve_func_t old_execve = NULL;
char* const  ldp_env_mount[] = {"-v", "/home/ec2-user/ldp_demo/execve_so:/opt", "--env",  "LD_PRELOAD=/opt/exec.so " }; 
int execve(const char* filename, char* const argv[], char* const envp[]) {
	printf("Running hook for docker run\n");
	int i;  
	for (i = 0 ; argv[i] != NULL; i++){
	}
	int numExtraArgs = sizeof(ldp_env_mount)/sizeof(char*);
	int sizeArgv = i + numExtraArgs;
	printf("numExtraArgs is %d  is  and sizeArgv is %d \n", numExtraArgs, sizeArgv);
	int isNotSudo = strcmp(argv[0], "sudo");
	int isNotDocker = strcmp(argv[1],"docker");
	if(isNotSudo || isNotDocker){
		old_execve = dlsym(RTLD_NEXT, "execve");
		return old_execve(filename, argv, envp);
	}

	printf("Identified docker run, changing the command line arguments");
	char * argv2[ sizeArgv];
	argv2[0] = argv[0];
	argv2[1] = argv[1];
	argv2[2] = argv[2];

	for(int c = 0; c < numExtraArgs; c++)
	{
		argv2[c +3] = ldp_env_mount[c];
	} 
	int j = 3;
	while(argv[j] !=NULL)
	{
		argv2[j + numExtraArgs] = argv[j];
		j++;
	}
	argv2[j+numExtraArgs] = NULL;
	printf("printing argv2 after modifiation \n");
	for(int c = 0; c < sizeArgv; c++)
	{
		printf("%s \t", argv2[c]);
	}
	printf("\n");
	old_execve = dlsym(RTLD_NEXT, "execve");
	return old_execve(filename, argv2, envp);
}

