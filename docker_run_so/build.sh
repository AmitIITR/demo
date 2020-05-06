#!/bin/bash
gcc -std=c99 -o docker_run.so -shared docker_run.c -Wall -Wfatal-errors -fPIC -g -ldl
