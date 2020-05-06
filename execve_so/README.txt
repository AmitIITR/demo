Compile command:(You may use build.sh, might need to give execute permission) 
gcc -std=c99 -o exec.so -shared java_exec.c -Wall -Wfatal-errors -fPIC -g -ldl



Usage:
export LD_PRELOAD=/$PWD/exec.so

start a bash shell(run command bash in your terminal) in the shell where above was set.




