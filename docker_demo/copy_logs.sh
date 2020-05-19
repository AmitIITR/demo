#!/bin/bash
export LD_PRELAOD=

 sudo docker ps | egrep -v 'rabb|db' | awk '{print $1}' | grep -v CONT  > cc.txt

filename='cc.txt'
echo Start
while read p; do 
    echo $p
    sudo docker container cp $p:/tmp/agent.log /tmp/logs/$p.log
done < $filename
