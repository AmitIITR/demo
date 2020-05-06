/* Filename: java_exec.c
 * This code is written to modify java command line arguments and 
 * hooking inception java agent.
 *
 * Example:
 * origional command: java -jar HelloWorld-all-1.0.jar
 *
 * modified by command: java -javaagent:HelloWorldAgent-1.0-SNAPSHOT.jar -jar HelloWorld-all-1.0.jar
 *
 * compile command: gcc -std=c99 -o exec.so -shared java_exec.c -Wall -Wfatal-errors -fPIC -g -ldl
 *
 */

#define _GNU_SOURCE
#include <unistd.h>
#include<fcntl.h> 
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>


typedef ssize_t (*execve_func_t)(const char* filename, char* const argv[], char* const envp[]);
static execve_func_t old_execve = NULL;
char* const javaAgent = "-javaagent:HelloWorldAgent-1.0-SNAPSHOT.jar"; 
int execve(const char* filename, char* const argv[], char* const envp[]) {
	printf("Running hook for Java Agent\n");
	int i;  
	for (i = 0 ; argv[i] != NULL; i++){
	}
	int sizeArgv = i +1;
	if(strcmp(argv[0], "java")){
		old_execve = dlsym(RTLD_NEXT, "execve");
		return old_execve(filename, argv, envp);
	}

	printf("java process is starting, changing the command line arguments");
	char * argv2[ sizeArgv + 1];
	argv2[0] = argv[0];
	argv2[1] = javaAgent;
	//argv2[1] = "-javaagent:HelloWorldAgent-1.0-SNAPSHOT.jar";
	int j = 1;
	while(argv[j] !=NULL)
	{
		argv2[j +1] = argv[j];
		j++;
	}
	argv2[j+1] = NULL;

	old_execve = dlsym(RTLD_NEXT, "execve");
	return old_execve(filename, argv2, envp);
}

