package main

import (
	"goProxy/core/config"
	"goProxy/core/server"
	"io"
	"log"
	"time"
)

func main() {

	//Disable Error Logging
	log.SetOutput(io.Discard)

	config.Load()

	go server.Serve()
	go server.Monitor()

	//Keep server running
	for {
		time.Sleep(1 * time.Second)
	}
}
