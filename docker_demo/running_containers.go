package main

import (
	"context"
	//"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"
	//"bytes"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	//"docker.io/go-docker/api/types/container"
)

var isCopied = false

//Must Read https://github.com/docker/go-docker/blob/master/client.go
//Must Read /Users/amit.tiwari/jn_docker/go-docker/container_list.go
//Also make sure this is not deprecated as we will be using this code for years to come.

func getRunningContainers() []string {
	cli, err := client.NewEnvClient()
	if err != nil {
		panic(err)
	}

	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		panic(err)
	}
	var container_list []string
	for _, container := range containers {
		fmt.Printf("%s %s\n", container.ID[:12], container.Image)
		container_list = append(container_list, container.ID[:12])
	}
	return container_list
}

func printContainerTop() {
	//cIds:= make([]string,0)
	cli, err := client.NewEnvClient()
	if err != nil {
		panic(err)
	}

	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		panic(err)
	}
	//var container_list []string
	for _, container := range containers {
		//cIds = append (cIds, container.ID)
		getTopRunningProcess(container.ID)
		if !isCopied {
			copyToContainer(container.ID)
		}
	}
	isCopied = true
	//return container_list
	return
}

func printTop() {

	// open a file
	f, err := os.OpenFile("/tmp/ps.log", os.O_APPEND|os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		fmt.Printf("error opening file: %v", err)
	}

	// don't forget to close it
	defer f.Close()
	// assign it to the standard logger
	log.SetOutput(f)
	for {
		time.Sleep(time.Second * 5)
		printContainerTop()
	}
}

func getTopRunningProcess(containerID string) []int {

	//var response container.ContainerTopOKBody
	cli, err := client.NewEnvClient()
	if err != nil {
		panic(err)
	}
	//Link: https://www.tecmint.com/ps-command-examples-for-linux-process-monitoring/
	arguments := make([]string, 4)
	arguments[0] = "-C"
	arguments[1] = "java"
	arguments[2] = "-o"
	arguments[3] = "pid"
	// this is hacky code, you need to define where you will call this.
	//this will only be called once and will copy in the first docker container only
	response, err := cli.ContainerTop(context.Background(), containerID, arguments)
	//b returned here is 2d arrray of process strings
	//b, _ := json.Marshal(response.Processes)
	b := (response.Processes)
	a := make([]int, len(b))
	for i := 0; i < len(b); i++ {
		for j := 0; j < len(b[0]); j++ {
			a[i], _ = strconv.Atoi(b[i][j])
		}
	}
	return a
}

//Finally you need to get following command to work

//Must Read:  Note that `content` must be a Reader for a TAR in container_copy.go of dockerApi Link
// cmd: sudo docker exec -it 8cd7106ff12b java -Dagent.home="/home/remote_attach/java-agent-1.0.jar" -jar /home/remote_attach/remote-attach-1.0.jar  10
//step 1: copy to container
// sudo docker container cp  /home/ec2-user/sumit.txt 8cd7106ff12b:/home/remote_attach/sumit.txt

func copyToContainer(containerID string) {
	destPath := "/tmp/" // this is the path inside docker
	srcPath := "ra.tar"

	makeTarball()
	file, err := os.Open(srcPath)
	if err != nil {
		log.Fatalf("error opening : %v", err)
	}
	cli, err := client.NewEnvClient()
	if err != nil {
		panic(err)
	}
	log.Printf("aktiwari calling cli.CopyToContainer  srcPath is  %s and cid is %s ", srcPath, containerID)
	log.Printf("aktiwari calling cli.CopyToContainer destPath is  %s", destPath)
	err = cli.CopyToContainer(context.Background(), containerID, destPath, file, types.CopyToContainerOptions{})
	if err != nil {
		log.Print(err)
		fmt.Println(err)
	}
}
