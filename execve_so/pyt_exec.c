/* Filename: pyt_exec.c
 * This code is written to modify python command line arguments and 
 * hooking inception python agent.
 *
 * Example:
 * compile command: gcc -std=c99 -o libinceptionappagentproc.so -shared pyt_exec.c -Wall -Wfatal-errors -fPIC -g -ldl
 * 
 * Output:
 * prints if the interpreter for command was python based on first line
 */


#define _GNU_SOURCE
#include <unistd.h>
#include<fcntl.h> 
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <string.h>


typedef ssize_t (*execve_func_t)(const char* filename, char* const argv[], char* const envp[]);
static execve_func_t old_execve = NULL;

bool isInterpretorPython(char * filename) {
	//printf("line 27"); 
	char c[1024*64];
	FILE *fptr;
	//printf("line 29"); 
	if ((fptr = fopen(filename, "r")) == NULL) {
		return false;
	}
	//printf("line 32"); 
	// reads text until newline is encountered
	fscanf(fptr, "%[^\n]", c);
	//printf("line 35"); 
	if (strstr(c, "python") != NULL) {
		//printf("\n characters %c , %c, %c\n", c[0], c[1], c[2]);
		//printf("line 38"); 
		if((c[0] == '#') && (c[1] == '!') && (c[2] == '/')){
			printf("python interpretor since first line of executable contains both python and  #!/\n");
			//printf("first line of file:\n%s\n\n", c);
			return true;
		}
	} 
	fclose(fptr);
	return false;
}

void runLs(){
	printf("\n This is before execve call of ls -l -a /opt/\n");	
	char *args[] = {"/bin/ls", "-l", "-a", "/opt/"};
	char *env_args[] = {"/bin", (char*)0};
	execve(args[0], args, env_args);
}

void findOT(){
	//printf("%s",system("whereis ls"));
}

int applyPythonAgent(const char* filename, char* const argv[], char* const envp[]){


	char * appends[] = {"/usr/local/bin/opentelemetry-instrument", "--trace-exporter", "inception", "-s", "python-flask"};
	int appendLen = sizeof(appends)/sizeof(char *);
	if(strcmp(filename, "opentelemetry-instrument") == 0){
		return 0;
	}
	int i;  
	for (i = 0; argv[i] != NULL; i++){
	}
	char *args[i+appendLen + 1];    //+1 for NULL in the end.
	for (int j = 0 ;j < appendLen + 1 ; j++){
		args[j] = appends[j];
	}
	for (int j = 0 ;j < i + 1 ; j++){
		args[j+appendLen] = argv[j];
	}
	args[i+appendLen] = NULL;
	char *env_args[] = {"/bin", (char*)0};
	printf("Python script found, starting new process with args \n");
	printf("Origional: \t");	
	for(int j  = 0 ;j < appendLen; j++){
		printf(" %s \t", args[j]);
	}
	printf("\n This is before execve call with new args\n");	
	execve(args[0], args, env_args);
	return 0;
}

int execve(const char* filename, char* const argv[], char* const envp[]) {
	//printf("LD_PRELOAD: Running hook for Python Agent\n");
	//printf("filename: %s\n", filename);
	if (strstr(filename, "ls") != NULL){

		old_execve = dlsym(RTLD_NEXT, "execve");
		old_execve(filename, argv, envp);
	}

	if(strstr(filename, "opentelemetry") != NULL){
		old_execve = dlsym(RTLD_NEXT, "execve");

		printf("opentelemetry: ");	
		for(int j= 0 ;argv[j] != NULL; j++){
			printf("%s \t", argv[j]);
		}
		printf("\n");	
		return old_execve(filename, argv, envp);

	}
	//printf("line 53"); 
	if(isInterpretorPython((char*)filename)){
		//runLs();
		//printf("line 56"); 
		//findOT();		
		printf("LD_PRELOAD: %s, is python interpreted\n", filename);
		applyPythonAgent(filename, argv, envp )	;
	}

	old_execve = dlsym(RTLD_NEXT, "execve");
	return old_execve(filename, argv, envp);
}
