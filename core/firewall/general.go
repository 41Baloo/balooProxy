package firewall

import (
	"sync"
)

var (
	Mutex = &sync.RWMutex{}

	//store unknown fingerprints for ratelimiting
	UnkFps = map[string]int{}
	//sliding window, to keep track of fingerprints
	WindowUnkFps = map[int]map[string]int{}

	//store bypassing ips for ratelimiting
	AccessIps = map[string]int{}
	//sliding window, to keep track of ips
	WindowAccessIps = map[int]map[string]int{}

	//store ips that didnt have verification cookie set for ratelimiting
	AccessIpsCookie = map[string]int{}
	//sliding window, to keep track of ips
	WindowAccessIpsCookie = map[int]map[string]int{}

	//"cache" encryption result of ips for 2 minutes in order to have less load on the proxy
	//Using syncMap here instead of CacheIps = map[string]string{}, since this value should only be written to once per 2 minutes and readonly the rest of the time
	CacheIps = sync.Map{}

	//"cache" captcha images to for 2 minutes in order to have less load on the proxy
	//CacheImgs = map[string]string{}
	CacheImgs = sync.Map{}

	Connections = map[string]string{}
)
