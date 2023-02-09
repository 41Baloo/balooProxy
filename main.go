package main

import (
	"goProxy/core/config"
	"goProxy/core/server"
	"io"
	"log"
)

func main() {

	//Disable Error Logging
	log.SetOutput(io.Discard)

	config.Load()

	go server.Serve()
	go server.Monitor()

	//Keep server running
	select {}
}
