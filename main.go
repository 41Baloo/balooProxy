package main

import (
	"fmt"
	"goProxy/core/config"
	"goProxy/core/pnc"
	"goProxy/core/server"
	"io"
	"log"
	"os"
)

func main() {

	logFile, err := os.OpenFile("crash.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()

	pnc.InitHndl()

	defer pnc.PanicHndl()

	//Disable Error Logging
	log.SetOutput(io.Discard)

	fmt.Println("Starting Proxy ...")

	config.Load()

	fmt.Println("Loaded Config ...")

	go server.Serve()
	go server.Monitor()

	fmt.Println("Started!")

	//Keep server running
	select {}
}
