package utils

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"time"
)

func LogHeapProfile() {
	f, err := os.Create(fmt.Sprintf("heap_%v.prof", time.Now().Unix()))
	if err != nil {
		fmt.Println("Could not create heap profile: ", err)
		return
	}
	defer f.Close()

	runtime.GC() // get up-to-date statistics
	if err := pprof.WriteHeapProfile(f); err != nil {
		fmt.Println("Could not write heap profile: ", err)
	}
}

func LogGoroutineProfile() {
	f, err := os.Create(fmt.Sprintf("goroutine_%v.prof", time.Now().Unix()))
	if err != nil {
		fmt.Println("Could not create goroutine profile: ", err)
		return
	}
	defer f.Close()

	if err := pprof.Lookup("goroutine").WriteTo(f, 0); err != nil {
		fmt.Println("Could not write goroutine profile: ", err)
	}
}
