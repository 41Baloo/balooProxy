package pnc

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"
)

var logFile *os.File

func InitHndl() {
	var err error
	logFile, err = os.OpenFile("crash.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}
}

func PanicHndl() {
	if r := recover(); r != nil {
		stackTrace := make([]byte, 4096000)
		runtime.Stack(stackTrace, false)

		errMsg := fmt.Sprintf("[ "+time.Now().Format("15:05:04")+" ]: Caught Panic: %v\n\n%s\n", r, bytes.TrimRight(stackTrace, "\x00"))
		logFile.WriteString(errMsg)
		panic(r)
	}
}

func LogError(msg string) {
	errMsg := fmt.Sprintf("[ "+time.Now().Format("15:05:04")+" ]: Error: %s\n", msg)
	logFile.WriteString(errMsg)
}
