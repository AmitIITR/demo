package main

import (
		"context"
		"fmt"
		"encoding/json"
		"time"
		"os"
		"log"
		//"bytes"
		"github.com/docker/docker/api/types"
		"github.com/docker/docker/client"
		//"docker.io/go-docker/api/types/container"
       )


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
		container_list = append (container_list, container.ID[:12])
	}
	return container_list
}


func printContainerTop(){
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
	}
	//return container_list
	return
}

func printTop(){

	// open a file
        f, err := os.OpenFile("/tmp/ps.log", os.O_APPEND | os.O_CREATE | os.O_RDWR, 0666)
        if err != nil {
            fmt.Printf("error opening file: %v", err)
        }

        // don't forget to close it
        defer f.Close()

        // assign it to the standard logger
        log.SetOutput(f)
	for{
		time.Sleep(time.Second*5)
		printContainerTop()
	}
}

func getTopRunningProcess(containerID string){

        //var response container.ContainerTopOKBody
	cli, err := client.NewEnvClient()
		if err != nil {
			panic(err)
		}
        arguments :=   make([]string,0) 
	response, err := cli.ContainerTop(context.Background(), containerID, arguments)
		if err != nil {
			panic(err)
		}
	b,_ := json.Marshal(response.Processes)
	//fmt.Println(string(b))
	//log.Output(1, string(b))
	log.Print( string(b))
	return
}
