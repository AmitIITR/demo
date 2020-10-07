#!/bin/bash

gcc -std=c99 -o libinceptionappagentproc.so -shared java_exec.c -Wall -Wfatal-errors -fPIC -g -ldl
