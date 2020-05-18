package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

func getNSpid(pid int) (int, error) {
	filename := "/proc/" + strconv.Itoa(pid) + "/status"
	fmt.Println(filename)

	readFile, err := os.Open(filename)

	if err != nil {
		log.Fatalf("failed to open file: %s", err)
	}

	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)
	var fileTextLines []string

	for fileScanner.Scan() {
		fileTextLines = append(fileTextLines, fileScanner.Text())
	}

	readFile.Close()

	for _, eachline := range fileTextLines {
		//fmt.Println(eachline)
		if strings.Contains(eachline, "NSpid:") {
			words := strings.Fields(eachline)
			fmt.Println(words[2])
			return strconv.Atoi(words[2])
		}

	}
	return int(0), errors.New("Did not get NSpid for the given pid")
}
