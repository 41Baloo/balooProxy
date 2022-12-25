package main

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"

	"github.com/inancgumus/screen"
	"github.com/shirou/gopsutil/cpu"
)

var (

	//Secret keys are the keys used to encrypt and decrypt the client's IP address.
	//IMPORTANT: PLEASE CHANGE THESE WHEN SETTING THIS SOURCE UP. (https://www.random.org/strings/?num=1&len=20&digits=on&upperalpha=on&loweralpha=on&unique=on&format=html&rnd=new)
	CookieSecretKey  = "RE2lsXJdc2hBOd8cOmv8"
	JsSecretKey      = "ngJTYj8jfWZGlavb3fsN"
	CaptchaSecretKey = "1vgFzfZkPvEzXfA4tTdC"

	backend = ""
	scheme  = "http"

	stage            = 1
	stageManuallySet = false

	maxLogs  = 10
	lastLogs = []string{}

	//Ratelimit values
	getFingerprintRequestRL = 8
	fingerprintRequestRL    = 100
	IPRequestRL             = 120
	IPChallengeRequestRL    = 40

	cw               ConnectionWatcher
	connections      = map[string]string{}
	totalRequests    = 0
	bypassedRequests = 0

	prevRequests = 0
	prevBypassed = 0

	requestsPerSecond         = 0
	requestsBypassedPerSecond = 0

	mutex = &sync.Mutex{}

	//Known fingerprints along with what browser/tool/bot/etc they belong to
	fingerprints = map[string]string{
		//Windows
		"0x1301,0x1302,0x1303,0xc02b,0xc02f,0xc02c,0xc030,0xcca9,0xcca8,0xc013,0xc014,0x9c,0x9d,0x2f,0x35,0x583235353139,0x437572766550323536,0x437572766550333834,0x0,":                                                                        "Chromium",
		"0x1303,0x1302,0xc02b,0xc02f,0xcca9,0xcca8,0xc02c,0xc030,0xc00a,0xc009,0xc013,0xc014,0x9c,0x9d,0x2f,0x35,0x437572766550323536,0x437572766550333834,0x437572766550353231,0x437572766549442832353629,0x437572766549442832353729,0x0,":     "Firefox",
		"0x1303,0x1302,0xc02b,0xc02f,0xcca9,0xcca8,0xc02c,0xc030,0xc013,0xc014,0x9c,0x9d,0x2f,0x35,0x437572766550323536,0x437572766550333834,0x437572766550353231,0x437572766549442832353629,0x437572766549442832353729,0x0,":                   "Firefox-Dev",
		"0x1301,0x1302,0x1302,0x1303,0xc02b,0xc02f,0xc02c,0xc030,0xcca9,0xcca8,0xc013,0xc014,0x9c,0x9d,0x2f,0x35,0x583235353139,0x437572766550323536,0x437572766550333834,0x0,":                                                                 "Edge",
		"0x1303,0x1302,0xc02b,0xc02f,0xcca9,0xcca8,0xc02c,0xc030,0xc00a,0xc009,0xc013,0xc014,0x9c,0x9d,0x2f,0x35,0xa,0x437572766550323536,0x437572766550333834,0x437572766550353231,0x437572766549442832353629,0x437572766549442832353729,0x0,": "Tor",

		//IPhone
		"0x1301,0x1302,0x1303,0xc02c,0xc02b,0xcca9,0xc030,0xc02f,0xcca8,0xc00a,0xc009,0xc014,0xc013,0x9d,0x9c,0x35,0x2f,0xc008,0xc012,0xa,0x583235353139,0x437572766550323536,0x437572766550333834,0x437572766550353231,0x0,": "Safari",

		//Android
		"0xc02c,0xc02f,0xc02b,0x9f,0x9e,0xc032,0xc02e,0xc031,0xc02d,0xa5,0xa1,0xa4,0xa0,0xc028,0xc024,0xc014,0xc00a,0xc02a,0xc026,0xc00f,0xc005,0xc027,0xc023,0xc013,0xc009,0xc029,0xc025,0xc00e,0xc004,0x6b,0x69,0x68,0x39,0x37,0x36,0x67,0x3f,0x3e,0x33,0x31,0x30,0x9d,0x9c,0x3d,0x35,0x3c,0x2f,0xff,0x437572766550353231,0x437572766550333834,0x4375727665494428323229,0x0,": "Dalvik",
	}

	botFingerprints = map[string]string{
		//Bots
		"0xc030,0x9f,0xcca9,0xcca8,0xccaa,0xc02b,0xc02f,0x9e,0xc024,0xc028,0x6b,0xc023,0xc027,0x67,0xc00a,0xc014,0x39,0xc009,0xc013,0x33,0x9d,0x9c,0x3d,0x3c,0x35,0x2f,0xff,0x437572766550323536,0x437572766550353231,0x437572766550333834,0x0,":                                                                                                                                                                                                                                       "Checkhost",
		"0x1303,0x1301,0x1305,0x1304,0xc030,0xc02c,0xc028,0xc024,0xc014,0xc00a,0xa3,0x9f,0x6b,0x6a,0x39,0x38,0x88,0x87,0x9d,0x3d,0x35,0x84,0xc02f,0xc02b,0xc027,0xc023,0xc013,0xc009,0xa2,0x9e,0x67,0x40,0x33,0x32,0x9a,0x99,0x45,0x44,0x9c,0x3c,0x2f,0x96,0x41,0xff,0x437572766550323536,0x4375727665494428333029,0x437572766550353231,0x437572766550333834,0x0,":                                                                                                                     "Host-Tracker",
		"0x1303,0x1301,0xc02f,0xc02b,0xc030,0xc02c,0x9e,0xc027,0x67,0xc028,0x6b,0xa3,0x9f,0xcca9,0xcca8,0xccaa,0xc0af,0xc0ad,0xc0a3,0xc09f,0xc05d,0xc061,0xc057,0xc053,0xa2,0xc0ae,0xc0ac,0xc0a2,0xc09e,0xc05c,0xc060,0xc056,0xc052,0xc024,0x6a,0xc023,0x40,0xc00a,0xc014,0x39,0x38,0xc009,0xc013,0x33,0x32,0x9d,0xc0a1,0xc09d,0xc051,0x9c,0xc0a0,0xc09c,0xc050,0x3d,0x3c,0x35,0x2f,0xff,0x437572766550323536,0x4375727665494428333029,0x437572766550353231,0x437572766550333834,0x0,": "Postman",

		//Tools
		"0x1303,0x1301,0xc02c,0xc030,0x9f,0xcca9,0xcca8,0xccaa,0xc02b,0xc02f,0x9e,0xc024,0xc028,0x6b,0xc023,0xc027,0x67,0xc00a,0xc014,0x39,0xc009,0xc013,0x33,0x9d,0x9c,0x3d,0x3c,0x35,0x2f,0xff,0x437572766550323536,0x4375727665494428333029,0x437572766550353231,0x437572766550333834,0x0,":                                                                                                                          "Curl",
		"0xc02c,0xc028,0xc024,0xc014,0xc00a,0xa5,0xa1,0x9f,0x6b,0x69,0x68,0x39,0x37,0x36,0x88,0x86,0x85,0xc032,0xc02e,0xc02a,0xc026,0xc00f,0xc005,0x9d,0x3d,0x35,0x84,0xc02f,0xc02b,0xc027,0xc023,0xc013,0xc009,0xa4,0xa0,0x9e,0x67,0x3f,0x3e,0x33,0x31,0x30,0x45,0x43,0x42,0xc031,0xc02d,0xc029,0xc025,0xc00e,0xc004,0x9c,0x3c,0x2f,0x41,0xff,0x437572766550353231,0x437572766550333834,0x4375727665494428323229,0x0,": "Aio-http",

		//Crawler
		"0x1303,0x1301,0xc02c,0xc030,0xc02b,0xc02f,0xcca9,0xcca8,0x9f,0x9e,0xccaa,0xc0af,0xc0ad,0xc0ae,0xc0ac,0xc024,0xc028,0xc023,0xc027,0xc00a,0xc014,0xc009,0xc013,0xc0a3,0xc09f,0xc0a2,0xc09e,0x6b,0x67,0x39,0x33,0x9d,0x9c,0xc0a1,0xc09d,0xc0a0,0xc09c,0x3d,0x3c,0x35,0x2f,0xff,0x437572766550323536,0x4375727665494428333029,0x437572766550353231,0x437572766550333834,0x0,":                                                                                                                                                                                                                                                                                                                                                                                                                                 "Unsolicited Crawler",
		"0xc087,0xcca9,0xc0ad,0xc00a,0xc02b,0xc086,0xc0ac,0xc009,0xc008,0xc030,0xc08b,0xcca8,0xc014,0xc02f,0xc08a,0xc013,0xc012,0x9d,0xc07b,0xc09d,0x35,0x84,0x9c,0xc07a,0xc09c,0x2f,0x41,0xa,0x9f,0xc07d,0xccaa,0xc09f,0x39,0x88,0x9e,0xc07c,0xc09e,0x33,0x45,0x16,0x437572766550333834,0x437572766550353231,0x4375727665494428323129,0x4375727665494428313929,0x0,":                                                                                                                                                                                                                                                                                                                                                                                                                                              "Unsolicited Cralwer",
		"0xc02c,0xc028,0xc024,0xc014,0xc00a,0xa5,0xa3,0xa1,0x9f,0x6b,0x6a,0x69,0x68,0x39,0x38,0x37,0x36,0x88,0x87,0x86,0x85,0xc032,0xc02e,0xc02a,0xc026,0xc00f,0xc005,0x9d,0x3d,0x35,0x84,0xc02f,0xc02b,0xc027,0xc023,0xc013,0xc009,0xa4,0xa2,0xa0,0x9e,0x67,0x40,0x3f,0x3e,0x33,0x32,0x31,0x30,0x9a,0x99,0x98,0x97,0x45,0x44,0x43,0x42,0xc031,0xc02d,0xc029,0xc025,0xc00e,0xc004,0x9c,0x3c,0x2f,0x96,0x41,0x7,0xc011,0xc007,0xc00c,0xc002,0x5,0x4,0xc012,0xc008,0x16,0x13,0x10,0xd,0xc00d,0xc003,0xa,0xff,0x437572766550353231,0x4375727665494428323829,0x4375727665494428323729,0x437572766550333834,0x4375727665494428323629,0x4375727665494428323229,0x4375727665494428313429,0x4375727665494428313329,0x4375727665494428313129,0x4375727665494428313229,0x43757276654944283929,0x4375727665494428313029,0x0,": "Unsolicited Crawler",
	}

	forbiddenFingerprints = map[string]string{
		"0x1303,0x1302,0xc02f,0xc02b,0xc030,0xc02c,0x9e,0xc027,0x67,0xc028,0x6b,0x9f,0xcca9,0xcca8,0xccaa,0xc0af,0xc0ad,0xc0a3,0xc09f,0xc05d,0xc061,0xc053,0xc0ae,0xc0ac,0xc0a2,0xc09e,0xc05c,0xc060,0xc052,0xc024,0xc023,0xc00a,0xc014,0x39,0xc009,0xc013,0x33,0x9d,0xc0a1,0xc09d,0xc051,0x9c,0xc0a0,0xc09c,0xc050,0x3d,0x3c,0x35,0x2f,0xff,0x437572766550323536,0x4375727665494428333029,0x437572766550353231,0x437572766550333834,0x437572766549442832353629,0x437572766549442832353729,0x437572766549442832353829,0x437572766549442832353929,0x437572766549442832363029,0x0,":                                             "Http-Flood (1)",
		"0x1303,0x1301,0xc02f,0xc02b,0xc030,0xc02c,0x9e,0xc027,0x67,0xc028,0x6b,0xa3,0x9f,0xcca9,0xcca8,0xccaa,0xc0af,0xc0ad,0xc0a3,0xc09f,0xc05d,0xc061,0xc057,0xc053,0xa2,0xc0ae,0xc0ac,0xc0a2,0xc09e,0xc05c,0xc060,0xc056,0xc052,0xc024,0x6a,0xc023,0x40,0xc00a,0xc014,0x39,0x38,0xc009,0xc013,0x33,0x32,0x9d,0xc0a1,0xc09d,0xc051,0x9c,0xc0a0,0xc09c,0xc050,0x3d,0x3c,0x35,0x2f,0xff,0x437572766550323536,0x4375727665494428333029,0x437572766550353231,0x437572766550333834,0x437572766549442832353629,0x437572766549442832353729,0x437572766549442832353829,0x437572766549442832353929,0x437572766549442832363029,0x0,": "Headless Browser",
		"0x1301,0x1302,0x1303,0xc02b,0xc02f,0xc02c,0xc030,0xcca9,0xcca8,0xc013,0xc014,0x9c,0x9d,0x2f,0x35,0xa,0x4375727665494428313636393629,0x583235353139,0x437572766550323536,0x437572766550333834,0x0,": "Headless Browser",
	}

	//store fingerprint requests for ratelimiting
	tcpRequests = map[string]int{}

	//store unknown fingerprints for ratelimiting
	unkFps = map[string]int{}

	//store bypassing ips for ratelimiting
	accessIps = map[string]int{}

	//store ips that didnt have verification cookie set for ratelimiting
	accessIpsCookie = map[string]int{}

	//"cache" encryption result of ips for 2 minutes in order to have less load on the backend
	cacheIps = map[string]string{}
)

func main() {

	//Disable error logging
	log.SetOutput(ioutil.Discard)

	//Let user know how to use script
	if len(os.Args) < 3 {
		fmt.Println("[ Usage ]: ./main [ Backend Ip ] [ Backend Scheme ] ( Cdn Mode )")
		os.Exit(1)
	}

	//Retrieve parameters
	backend = os.Args[1]
	scheme = os.Args[2]

	//Create reverseproxy to backend using the given parameters
	proxy := httputil.NewSingleHostReverseProxy(&url.URL{
		Scheme: scheme,
		Host:   backend,
	})

	//Create https server to handle requests
	server := http.Server{
		Addr:      ":443",
		ConnState: cw.OnStateChange,
		//Terminate Idle/Inactive connections
		IdleTimeout:       5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{
			GetConfigForClient: getConfigForClient,
		},
	}

	//Create http server to redirect to https
	httpServer := http.Server{
		Addr:      ":80",
		ConnState: cw.OnStateChange,
		//Terminate Idel/Inactive connections
		IdleTimeout:       5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}

	//Setting keepalive to false to better prevent ddos attacks from creating too many connections (play around with it. not sure if it's better on or off)
	server.SetKeepAlivesEnabled(false)

	fmt.Println("[ Reverse Proxy ]: Started on " + server.Addr)

	//Redirect http connections to https
	httpServer.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		totalRequests = totalRequests + 1

		http.Redirect(w, r, "https://"+r.Host+r.URL.Path+r.URL.RawQuery, http.StatusMovedPermanently)

	})

	//Handle requests
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		totalRequests = totalRequests + 1

		ip := strings.Split(r.RemoteAddr, ":")[0]

		//Retrieve information about the client
		mutex.Lock()
		tlsFp := connections[r.RemoteAddr]
		browser := fingerprints[tlsFp]
		botFp := botFingerprints[tlsFp]

		fpCount := unkFps[tlsFp]
		ipCount := accessIps[ip]
		ipCountCookie := accessIpsCookie[ip]

		encryptedIP := cacheIps[ip+fmt.Sprint(stage)]
		mutex.Unlock()

		//Ratelimit faster if client repeatedly fails the verification challenge (feel free to play around with the threshhold)
		if ipCountCookie > IPChallengeRequestRL {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "Blocked by BalooProxy.\nYou have been ratelimited. (R1)")
			return
		}

		//Ratelimit spamming Ips (feel free to play around with the threshhold)
		if ipCount > IPRequestRL {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "Blocked by BalooProxy.\nYou have been ratelimited. (R2)")
			return
		}

		//Ratelimit fingerprints that don't belong to major browsers
		if browser == "" {
			if fpCount > fingerprintRequestRL {
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprintf(w, "Blocked by BalooProxy.\nYou have been ratelimited. (R3)")
				return
			}

			mutex.Lock()
			unkFps[tlsFp] = unkFps[tlsFp] + 1
			mutex.Unlock()
		}

		//Block user-specified fingerprints
		if _, ok := forbiddenFingerprints[tlsFp]; ok {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "Blocked by BalooProxy.\nYour browser %s is not allowed.", forbiddenFingerprints[tlsFp])
			return
		}

		//Check if encryption-result is already "cached" to prevent load on reverse proxy
		if encryptedIP == "" {
			hr, _, _ := time.Now().Clock()
			switch stage {
			case 1:
				encryptedIP = encrypt(ip+tlsFp+fmt.Sprint(hr), CookieSecretKey)
			case 2:
				encryptedIP = encrypt(ip+tlsFp+fmt.Sprint(hr), JsSecretKey)
			case 3:
				encryptedIP = encrypt(ip+tlsFp+fmt.Sprint(hr), CaptchaSecretKey)
			}
			mutex.Lock()
			cacheIps[ip+fmt.Sprint(stage)] = encryptedIP
			mutex.Unlock()
		}

		//Check if client provided correct verification result
		if !strings.Contains(r.Header.Get("Cookie"), fmt.Sprintf("__bProxy_v=%s", encryptedIP)) {

			mutex.Lock()
			accessIpsCookie[ip] = accessIpsCookie[ip] + 1
			mutex.Unlock()

			//Debug
			/*
				if browser != "" || botFp != "" {
					access := "[ " + time.Now().Format("15:04:05") + " ] [ Debug ]: " + ip + " - \033[32m" + browser + botFp + "\033[0m - " + r.UserAgent() + " - " + r.RequestURI
					addLogs(access)
					mutex.Lock()
					accessIps[ip] = accessIps[ip] + 1
					mutex.Unlock()
				} else {
					access := "[ " + time.Now().Format("15:04:05") + " ] [ Debug ]: " + ip + " - \033[31mUNK (" + tlsFp + ")\033[0m - " + r.UserAgent() + " - " + r.RequestURI
					addLogs(access)
					mutex.Lock()
					accessIps[ip] = accessIps[ip] + 1
					mutex.Unlock()
				}
			*/

			//Respond with verification challenge if client didnt provide correct result/none
			switch stage {
			case 1:
				w.Header().Set("Set-Cookie", "__bProxy_v="+encryptedIP+"; SameSite=None; path=/; Secure")
				http.Redirect(w, r, r.URL.RequestURI(), http.StatusTemporaryRedirect)
				return
			case 2:
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprintf(w, `<script>document.cookie = '__bProxy_v=%s; SameSite=None; path=/; Secure';window.location.reload();</script>`, encryptedIP)
				return
			case 3:
				secretPart := encryptedIP[:6]
				publicPart := encryptedIP[6:]

				captchaImg := image.NewRGBA(image.Rect(0, 0, 100, 37))
				addLabel(captchaImg, 10, 10, secretPart)

				var buf bytes.Buffer
				if err := png.Encode(&buf, captchaImg); err != nil {
					fmt.Fprintf(w, `BalooProxy Error: Failed to encode captcha: %s`, err)
				}
				data := buf.Bytes()

				captchaData := base64.StdEncoding.EncodeToString(data)

				w.Header().Set("Content-Type", "text/html")

				fmt.Fprintf(w,
					`
					<center>
					<canvas id="image" width="100" height="37"></canvas><br>
					<input id="solution" type="text"></input>
					<button onclick="verify()">Verify</button>
					</center>
					<script>
						let canvas=document.getElementById("image");
						let ctx = canvas.getContext("2d");
						var image = new Image();
						image.onload = function() {
							ctx.drawImage(image, (canvas.width-image.width)/2, (canvas.height-image.height)/2);
						};
						image.src = "data:image/png;base64,%s";

						function verify(){
							let solution = document.getElementById("solution").value;
							document.cookie = '__bProxy_v='+solution+'%s; SameSite=None; path=/; Secure'; 
							location.reload();
						}
					</script>
					`, captchaData, publicPart)
				return
			}
		}

		//Access logs of clients that passed the challenge
		if browser != "" || botFp != "" {
			access := "[ " + time.Now().Format("15:04:05") + " ]: " + ip + " - \033[32m" + browser + botFp + "\033[0m - " + r.UserAgent() + " - " + r.RequestURI
			addLogs(access)
			mutex.Lock()
			accessIps[ip] = accessIps[ip] + 1
			mutex.Unlock()
		} else {
			access := "[ " + time.Now().Format("15:04:05") + " ]: " + ip + " - \033[31mUNK (" + tlsFp + ")\033[0m - " + r.UserAgent() + " - " + r.RequestURI
			addLogs(access)
			mutex.Lock()
			accessIps[ip] = accessIps[ip] + 1
			mutex.Unlock()
		}

		bypassedRequests++

		//Reserved proxy-paths
		switch r.URL.Path {
		case "/_bProxy/stats":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "Total Requests: %s\nBypassed Requests: %s\nTotal R/s: %s\nBypassed R/s: %s\nActive Connections: %s", fmt.Sprint(totalRequests), fmt.Sprint(bypassedRequests), fmt.Sprint(requestsPerSecond), fmt.Sprint(requestsBypassedPerSecond), fmt.Sprint(cw.Count()))
			return
		case "/_bProxy/fingerprint":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "IP: "+ip+"\nIP Requests: "+fmt.Sprint(ipCount)+"\nIP Challenge Requests: "+fmt.Sprint(accessIpsCookie[ip])+"\nFingerprint: "+encrypt(tlsFp, "goProxy")+"\nBrowser: "+browser+botFp)
			return
		case "/_bProxy/unknown":
			w.Header().Set("Content-Type", "text/plain")
			for unk, times := range unkFps {
				fmt.Fprintf(w, unk+": "+fmt.Sprint(times)+"\n")
			}
			return
		case "/_bProxy/admin":
			w.Header().Set("Content-Type", "text/plain")

			cpuUsage := ""
			result, err := cpu.Percent(0, false)
			if err != nil {
				cpuUsage = err.Error()
			} else {
				cpuUsage = fmt.Sprintf("%.2f", result[0])
			}

			ratelimitedIps := ""

			mutex.Lock()
			for ipCookie, count := range accessIpsCookie {
				if count > IPChallengeRequestRL {
					ratelimitedIps += ipCookie + " (" + fmt.Sprint(count) + ")\n"
				}
			}
			for ip, count := range accessIps {
				if count > IPRequestRL {
					ratelimitedIps += ip + " (" + fmt.Sprint(count) + ")\n"
				}
			}
			mutex.Unlock()

			ratelimitedFps := ""

			mutex.Lock()
			for fp, count := range unkFps {
				if count > fingerprintRequestRL {
					ratelimitedFps += fp + " (" + fmt.Sprint(count) + ")\n"
				}
			}
			mutex.Unlock()

			L4Ratelimited := ""

			mutex.Lock()
			for ip, count := range tcpRequests {
				if count > getFingerprintRequestRL {
					L4Ratelimited += ip + " (" + fmt.Sprint(count) + ")\n"
				}
			}
			mutex.Unlock()

			fmt.Fprintf(w, "Stage: "+fmt.Sprint(stage)+"\n\nCpu Usage: "+cpuUsage+"\n\nTotal R/s: "+fmt.Sprint(requestsPerSecond)+"\nPassed R/s: "+fmt.Sprint(requestsBypassedPerSecond)+"\n\nTotal Requests: "+fmt.Sprint(totalRequests)+"\nPassed Requests: "+fmt.Sprint(bypassedRequests)+"\nCurrent Connections: "+fmt.Sprint(cw.Count())+"\n\nRatelimited Ips:\n"+ratelimitedIps+"\nRatelimited Fps:\n"+ratelimitedFps+"\nL4 Requests:\n"+L4Ratelimited+"\n")

			return
		case "/_bProxy/stage":
			setStage, err := strconv.ParseInt(r.URL.Query().Get("stage"), 0, 64)
			if err != nil {
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprintf(w, "Error: "+err.Error())
				return
			}
			stage = int(setStage)
			if stage == 0 {
				stage = 1
				stageManuallySet = false
			} else {
				stageManuallySet = true
			}
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "Set stage to "+fmt.Sprint(stage))
			return
		}

		proxy.ServeHTTP(w, r)

	})

	//Start ssh based monitor
	go serverMonitor()

	//Start http server
	go httpServer.ListenAndServe()

	//Start https server (server.crt and server.key have to be your own ssl certificates)
	server.ListenAndServeTLS("server.crt", "server.key")
}

//HOOKS

// Hook for listening into clientHello of every request
func getConfigForClient(clientHello *tls.ClientHelloInfo) (*tls.Config, error) {

	ip := strings.Split(clientHello.Conn.RemoteAddr().String(), ":")[0]

	mutex.Lock()
	ipCount := accessIps[ip]
	ipCountCookie := accessIpsCookie[ip]
	mutex.Unlock()

	//Ignore ratelimited Ips
	if ipCount > IPRequestRL || ipCountCookie > IPChallengeRequestRL {
		return nil, nil
	}

	fingerprint := ""

	//Loop over clientHello parameters and ignore first elements of arrays since they may be randomised by certain browsers
	for _, suite := range clientHello.CipherSuites[1:] {
		fingerprint += fmt.Sprintf("0x%x", suite) + ","
	}

	for _, curve := range clientHello.SupportedCurves[1:] {
		fingerprint += fmt.Sprintf("0x%x", curve) + ","
	}
	for _, point := range clientHello.SupportedPoints[:1] {
		fingerprint += fmt.Sprintf("0x%x", point) + ","
	}

	//Remember what connection has what fingerprint for later use
	mutex.Lock()
	connections[fmt.Sprint(clientHello.Conn.RemoteAddr())] = fingerprint
	mutex.Unlock()

	return nil, nil
}

// Hook for listening into connection changes (specifically newly created once and terminated connections)
func (cw *ConnectionWatcher) OnStateChange(conn net.Conn, state http.ConnState) {

	ip := strings.Split(conn.RemoteAddr().String(), ":")[0]

	switch state {
	case http.StateNew:
		mutex.Lock()
		fpReq := tcpRequests[ip]
		successCount := accessIps[ip]
		challengeCount := accessIpsCookie[ip]
		cw.Add(1)
		tcpRequests[ip] = tcpRequests[ip] + 1
		mutex.Unlock()

		//We can ratelimit so extremely here because normal browsers will use http/2 and keep the connection open instead of making new once
		if (fpReq > getFingerprintRequestRL && (successCount < 1 && challengeCount < 1)) || fpReq > 500 {
			defer conn.Close()
			return
		}

	case http.StateHijacked, http.StateClosed:
		//Remove connection from list of fingerprints as it's no longer needed
		mutex.Lock()
		cw.Add(-1)
		delete(connections, fmt.Sprint(conn.RemoteAddr()))
		mutex.Unlock()
	}
}

//FUNCTIONS

func serverMonitor() {
	for {
		for i := 0; i < 120; i++ {
			screen.Clear()
			screen.MoveTopLeft()

			requestsPerSecond = totalRequests - prevRequests
			requestsBypassedPerSecond = bypassedRequests - prevBypassed

			prevRequests = totalRequests
			prevBypassed = bypassedRequests

			result, err := cpu.Percent(0, false)
			if err != nil {
				fmt.Println("[ Cpu Usage ]: " + err.Error())
			} else {
				fmt.Println("[ Cpu Usage ]: " + fmt.Sprintf("%.2f", result[0]))
			}

			if !stageManuallySet {
				if stage == 1 && requestsBypassedPerSecond > 250 {
					stage = 2
				} else if stage == 2 && requestsBypassedPerSecond > 1000 {
					stage = 3
				} else if stage == 3 && requestsBypassedPerSecond < 300 && requestsPerSecond < 2000 {
					stage = 2
				} else if stage == 2 && requestsBypassedPerSecond < 100 && requestsPerSecond < 500 {
					stage = 1
				}
			}

			fmt.Println("")

			fmt.Println("[ Stage ]: " + fmt.Sprint(stage))
			fmt.Println("[ Stage Locked ]: " + fmt.Sprint(stageManuallySet))

			fmt.Println("")

			fmt.Println("[ Total R/s ]: " + fmt.Sprint(requestsPerSecond))
			fmt.Println("[ Bypassed R/s ]: " + fmt.Sprint(requestsBypassedPerSecond))

			fmt.Println("")

			fmt.Println("[ Total Requests ]: " + fmt.Sprint(totalRequests))
			fmt.Println("[ Bypassed Requests ]: " + fmt.Sprint(bypassedRequests))
			fmt.Println("[ Total Connections ]: " + fmt.Sprint(cw.Count()))

			fmt.Println("")
			fmt.Println("[ Latest Logs ]")

			for _, log := range lastLogs {
				fmt.Println(log)
			}

			time.Sleep(1 * time.Second)
		}

		//Clear logs and maps every 2 minutes. (I know this is a lazy way to do it, tho for now it seems to be the most efficient and fast way to go about it)
		mutex.Lock()
		for tcpRequest := range tcpRequests {
			delete(tcpRequests, tcpRequest)
		}
		for unk := range unkFps {
			delete(unkFps, unk)
		}
		for ip := range accessIps {
			delete(accessIps, ip)
		}
		for ipCookie := range accessIpsCookie {
			delete(accessIpsCookie, ipCookie)
		}
		for cacheIp := range cacheIps {
			delete(cacheIps, cacheIp)
		}
		mutex.Unlock()
	}
}

func (cw *ConnectionWatcher) Count() int {
	return int(atomic.LoadInt64(&cw.n))
}

func (cw *ConnectionWatcher) Add(c int64) {
	atomic.AddInt64(&cw.n, c)
}

func encrypt(input string, key string) string {
	hasher := md5.New()
	hasher.Write([]byte(input + key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func addLabel(img *image.RGBA, x, y int, label string) {
	col := color.RGBA{200, 100, 0, 255}
	point := fixed.Point26_6{X: fixed.I(x), Y: fixed.I(y)}

	d := &font.Drawer{
		Dst:  img,
		Src:  image.NewUniform(col),
		Face: basicfont.Face7x13,
		Dot:  point,
	}
	d.DrawString(label)
}

func addLogs(entry string) {

	if len(lastLogs) > maxLogs {
		mutex.Lock()
		lastLogs = lastLogs[1:]
		lastLogs = append(lastLogs, entry)
		mutex.Unlock()
		for i, log := range lastLogs {
			fmt.Println("\033[" + fmt.Sprint(14+i) + ";1H\033[K" + log)
		}
		return
	}
	mutex.Lock()
	lastLogs = append(lastLogs, entry)
	mutex.Unlock()
	fmt.Println(entry)
}

//STRUCTS

type ConnectionWatcher struct {
	n int64
}
