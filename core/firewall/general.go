package firewall

import (
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
