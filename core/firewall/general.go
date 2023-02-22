package firewall

import (
	"goProxy/core/proxy"
	"net"
	"net/http"
	"strings"
	"sync"
)

var (
	Mutex = &sync.Mutex{}
	//store fingerprint requests for ratelimiting
	TcpRequests = map[string]int{}

	//store unknown fingerprints for ratelimiting
	UnkFps = map[string]int{}

	//store bypassing ips for ratelimiting
	AccessIps = map[string]int{}

	//store ips that didnt have verification cookie set for ratelimiting
	AccessIpsCookie = map[string]int{}

	//"cache" encryption result of ips for 2 minutes in order to have less load on the proxy
	//Using syncMap here instead of CacheIps = map[string]string{}, since this value should only be written to once per 2 minutes and readonly the rest of the time
	CacheIps = sync.Map{}

	//"cache" captcha images to for 2 minutes in order to have less load on the proxy
	//CacheImgs = map[string]string{}
	CacheImgs = sync.Map{}

	Connections = map[string]string{}
)

func OnStateChange(conn net.Conn, state http.ConnState) {

	remoteAddr := conn.RemoteAddr().String()

	ip := strings.Split(remoteAddr, ":")[0]

	switch state {
	case http.StateNew:
		Mutex.Lock()
		fpReq := TcpRequests[ip]
		successCount := AccessIps[ip]
		challengeCount := AccessIpsCookie[ip]
		Mutex.Unlock()

		//We can ratelimit so extremely here because normal browsers will send actual webrequests instead of only establishing connections
		if (fpReq > proxy.FailRequestRatelimit && (successCount < 1 && challengeCount < 1)) || fpReq > 500 {
			defer conn.Close()
			return
		}

		Mutex.Lock()
		TcpRequests[ip] = TcpRequests[ip] + 1
		Mutex.Unlock()
	case http.StateHijacked, http.StateClosed:
		//Remove connection from list of fingerprints as it's no longer needed
		Mutex.Lock()
		delete(Connections, remoteAddr)
		Mutex.Unlock()
	}
}
