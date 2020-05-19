//sudo docker exec -it 6ec4f4f8b21b java -Dagent.home="/tmp/home/ec2-user/java_agent/java-agent-1.0.jar"  -jar /tmp/home/ec2-user/java_agent/remote-attach-1.0.jar 8

package main

import (
	"context"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"strconv"
	"time"
)

func remote_attach(containerID string) {
	psArray := getTopRunningProcess(containerID)

	copyToContainer(containerID)
	for i := 0; i < len(psArray); i++ {
		fmt.Println("remote_attach  line 20, and  hpid is ", psArray[i])
		nspid, err := getNSpid(psArray[i])
		if err != nil {
			return
		}

		remote_attach_java(nspid, containerID)
	}
}

func remote_attach_java(pid int, containerID string) {
	fmt.Println("remote_attach_java  line 37, and  pid is ", pid)
	time.Sleep(time.Second * 5)
	cli, err := client.NewEnvClient()
	if err != nil {
		panic(err)
	}

	//containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		panic(err)
	}
	//var container_list []string
	//sudo docker exec -it 9ad6678b433b java -Dagent.home="/tmp/home/ec2-user/java_agent/java-agent-1.0.jar"  -jar /tmp/home/ec2-user/java_agent/remote-attach-1.0.jar 56
	cmdArray := []string{"java", "-Xbootclasspath/a:/tmp/home/ec2-user/java_agent_3/tools.jar", "-Dagent.home=/tmp/home/ec2-user/java_agent_3/java-agent-1.0.jar", "-jar", "/tmp/home/ec2-user/java_agent_3/remote-attach-1.0.jar", strconv.Itoa(pid)}
	//	for _, container := range containers {
	//cIds = append (cIds, container.ID)

	config := types.ExecConfig{
		AttachStdin:  false,
		AttachStdout: true,
		AttachStderr: true,
		//DetachKeys:   []byte{},
		Detach:     true,
		Cmd:        cmdArray,
		Tty:        false,
		Privileged: true,
		User:       "root",
		WorkingDir: "/tmp/home/ec2-user/java_agent_3/",
	}
	response, err := cli.ContainerExecCreate(context.Background(), containerID, config)
	if err != nil {
		fmt.Println("cli.ContainerExecCreate(context.Background(), container.ID, config) failed with error: ", err)
	}

	execStartCheck := types.ExecStartCheck{
		Detach: true,
		Tty:    false,
	}

	err = cli.ContainerExecStart(context.Background(), response.ID, execStartCheck)

	if err != nil {
		fmt.Println("cli.ContainerExecStart(context.Background(), response.ID, execStartCheck)  failed with error: ", err)
	}
	//	}
}
