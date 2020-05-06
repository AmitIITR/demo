Compile command:(You may use build.sh, might need to give execute permission) 
gcc -std=c99 -o docker_run.so -shared docker_run.c -Wall -Wfatal-errors -fPIC -g -ldl



Usage:
export LD_PRELOAD=/$PWD/docker_run.so

start a bash shell(run command bash in your terminal) in the shell where above was set.

