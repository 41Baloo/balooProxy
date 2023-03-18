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

var caughtCrashes = 0

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
			if caughtCrashes < 10 {
				caughtCrashes++
				logFile.WriteString("[ " + time.Now().Format("15:05:04") + " ]: Attempting to recover ...\n")
				main()
			} else {
				panic("[ balooProxy seems to be in a bad state. Please check crash.log for more information ]")
			}
		}
	}()

	//Disable Error Logging
	log.SetOutput(io.Discard)

	config.Load()

	go server.Serve()
	go server.Monitor()

	//Keep server running
	select {}
}
