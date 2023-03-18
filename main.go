package main

import (
	"goProxy/core/config"
	"goProxy/core/pnc"
	"goProxy/core/server"
	"io"
	"log"
	"os"
)

var caughtCrashes = 0

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

	config.Load()

	go server.Serve()
	go server.Monitor()

	//Keep server running
	select {}
}
