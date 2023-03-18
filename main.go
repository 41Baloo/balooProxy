package main

import (
	"bytes"
	"fmt"
	"goProxy/core/config"
	"goProxy/core/server"
	"io"
	"log"
	"os"
	"runtime"
	"time"
)

func main() {

	logFile, err := os.OpenFile("crash.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()

	defer func() {
		if r := recover(); r != nil {
			// Get the stack trace for the panic
			stackTrace := make([]byte, 4096)
			runtime.Stack(stackTrace, false)

			errMsg := fmt.Sprintf("[ "+time.Now().Format("15:05:04")+" ]: Caught Panic: %v\n\n%s\n", r, bytes.TrimRight(stackTrace, "\x00"))
			logFile.WriteString(errMsg)
			logFile.WriteString("[ " + time.Now().Format("15:05:04") + " ]: Attempting to recover ...\n")
			main()
		}
	}()

	//Disable Error Logging
	log.SetOutput(io.Discard)

	config.Load()

	go server.Serve()
	go server.Monitor()

	//panic("intentional crash")

	//Keep server running
	select {}
}
