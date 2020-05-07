package main

import (
		"context"
		"fmt"

		"github.com/docker/docker/api/types"
		"github.com/docker/docker/client"
       )

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
