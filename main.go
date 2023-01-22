package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"io/ioutil"
	"log"
	"math"
	"math/rand"
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
	"golang.org/x/term"

	"github.com/boltdb/bolt"
	"github.com/inancgumus/screen"
	"github.com/kor44/gofilter"
	"github.com/shirou/gopsutil/cpu"
)

var (

	//Secret keys are the keys used to encrypt and decrypt the client's IP address.
	//IMPORTANT: PLEASE CHANGE THESE WHEN SETTING THIS SOURCE UP. (https://www.random.org/strings/?num=1&len=20&digits=on&upperalpha=on&loweralpha=on&unique=on&format=html&rnd=new)
	CookieSecretKey  string
	JsSecretKey      string
	CaptchaSecretKey string

	cloudflareMode bool

	watchedDomain = ""
	maxLogs       = 10
	tWidth        = 100
	tHeight       = 100

	domainsMap sync.Map
	domainList = []string{}
	boltDb     *bolt.DB

	//Ratelimit values
	getFingerprintRequestRL int
	fingerprintRequestRL    int
	IPRequestRL             int
	IPChallengeRequestRL    int

	cw          ConnectionWatcher
	connections = map[string]string{}

	mutex      = &sync.Mutex{}
	printMutex = &sync.Mutex{}

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
		"0x1303,0x1301,0xc02c,0xc030,0x9f,0xcca9,0xcca8,0xccaa,0xc02b,0xc02f,0x9e,0xc024,0xc028,0x6b,0xc023,0xc027,0x67,0xc00a,0xc014,0x39,0xc009,0xc013,0x33,0x9d,0x9c,0x3d,0x3c,0x35,0x2f,0xff,0x437572766550323536,0x4375727665494428333029,0x437572766550353231,0x437572766550333834,0x437572766549442832353629,0x437572766549442832353729,0x437572766549442832353829,0x437572766549442832353929,0x437572766549442832363029,0x0,":                                                                                                                                                                                                                                                                                                                                                                              "DataForSeo",
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

	//"cache" encryption result of ips for 2 minutes in order to have less load on the proxy
	cacheIps = map[string]string{}

	//"cache" captcha images to for 2 minutes in order to have less load on the proxy
	cacheImgs = map[string]string{}
)

func main() {

	//Disable error logging
	log.SetOutput(io.Discard)

	//Register custom firewall rules values
	gofilter.RegisterField("ip.src", gofilter.FT_IP)
	gofilter.RegisterField("ip.country", gofilter.FT_STRING)
	gofilter.RegisterField("ip.asn", gofilter.FT_INT)
	gofilter.RegisterField("ip.engine", gofilter.FT_STRING)
	gofilter.RegisterField("ip.bot", gofilter.FT_STRING)
	gofilter.RegisterField("ip.fingerprint", gofilter.FT_STRING)
	gofilter.RegisterField("ip.requests", gofilter.FT_INT)
	gofilter.RegisterField("ip.http_requests", gofilter.FT_INT)
	gofilter.RegisterField("ip.challenge_requests", gofilter.FT_INT)

	gofilter.RegisterField("http.host", gofilter.FT_STRING)
	gofilter.RegisterField("http.version", gofilter.FT_STRING)
	gofilter.RegisterField("http.method", gofilter.FT_STRING)
	gofilter.RegisterField("http.query", gofilter.FT_STRING)
	gofilter.RegisterField("http.path", gofilter.FT_STRING)
	gofilter.RegisterField("http.user_agent", gofilter.FT_STRING)
	gofilter.RegisterField("http.cookie", gofilter.FT_STRING)
	gofilter.RegisterField("http.headers", gofilter.FT_STRING)
	gofilter.RegisterField("http.body", gofilter.FT_STRING)

	gofilter.RegisterField("proxy.stage", gofilter.FT_INT)
	gofilter.RegisterField("proxy.cloudflare", gofilter.FT_BOOL)
	gofilter.RegisterField("proxy.stage_locked", gofilter.FT_BOOL)
	gofilter.RegisterField("proxy.attack", gofilter.FT_BOOL)
	gofilter.RegisterField("proxy.bypass_attack", gofilter.FT_BOOL)
	gofilter.RegisterField("proxy.rps", gofilter.FT_INT)
	gofilter.RegisterField("proxy.rps_allowed", gofilter.FT_INT)

	//Read configuration json
	configJson, err := os.Open("config.json")
	if err != nil {
		panic("[ " + redText("!") + " ] [ " + redText(err.Error()) + " ]")
	}
	fmt.Println("[ " + redText("Opened config.json") + " ]")
	defer configJson.Close()
	configsFile, _ := io.ReadAll(configJson)
	var configuration Configuration
	json.Unmarshal(configsFile, &configuration)

	proxy := configuration.Proxy

	cloudflareMode = proxy.Cloudflare
	fmt.Println("[" + redText("+") + "] [ " + redText("Cloudflare Mode") + " ] > " + fmt.Sprint(proxy.Cloudflare))
	maxLogs = proxy.MaxLogLength
	fmt.Println("[" + redText("+") + "] [ " + redText("Log Length") + " ] > " + fmt.Sprint(proxy.MaxLogLength))

	if proxy.Secrets["cookie"] == "" {
		panic("[ " + redText("!") + " ] [ " + redText("Cookie Secret Is Empty") + " ]")
	}
	CookieSecretKey = proxy.Secrets["cookie"]
	fmt.Println("[" + redText("+") + "] [ " + redText("Cookie Secret") + " ] > XXXXXXXXXX" + CookieSecretKey[:10])
	if proxy.Secrets["javascript"] == "" {
		panic("[ " + redText("!") + " ] [ " + redText("Javascript Secret Is Empty") + " ]")
	}
	JsSecretKey = proxy.Secrets["javascript"]
	fmt.Println("[" + redText("+") + "] [ " + redText("JS Secret") + " ] > XXXXXXXXXX" + JsSecretKey[:10])
	if proxy.Secrets["captcha"] == "" {
		panic("[ " + redText("!") + " ] [ " + redText("Captcha Secret Is Empty") + " ]")
	}
	CaptchaSecretKey = proxy.Secrets["captcha"]
	fmt.Println("[" + redText("+") + "] [ " + redText("Captcha Secret") + " ] > XXXXXXXXXX" + CaptchaSecretKey[:10])

	if proxy.Ratelimits["requests"] == 0 {
		panic("[ " + redText("!") + " ] [ " + redText("Requests Ratelimit Is Empty (Please set it to a very high value if you want to \"disable\" it).") + " ]")
	}
	IPRequestRL = proxy.Ratelimits["requests"]
	fmt.Println("[" + redText("+") + "] [ " + redText("Request Ratelimit") + " ] > " + fmt.Sprint(IPRequestRL))
	if proxy.Ratelimits["unknownFingerprint"] == 0 {
		panic("[ " + redText("!") + " ] [ " + redText("Unknown Fingerprint Ratelimit Is Empty (Please set it to a very high value if you want to \"disable\" it).") + " ]")
	}
	fingerprintRequestRL = proxy.Ratelimits["unknownFingerprint"]
	fmt.Println("[" + redText("+") + "] [ " + redText("Unknown Fingerprint Ratelimit") + " ] > " + fmt.Sprint(fingerprintRequestRL))
	if proxy.Ratelimits["challengeFailures"] == 0 {
		panic("[ " + redText("!") + " ] [ " + redText("Challenge Failure Ratelimit Is Empty (Please set it to a very high value if you want to \"disable\" it).") + " ]")
	}
	IPChallengeRequestRL = proxy.Ratelimits["challengeFailures"]
	fmt.Println("[" + redText("+") + "] [ " + redText("Challenge Failure Ratelimit") + " ] > " + fmt.Sprint(IPChallengeRequestRL))
	if proxy.Ratelimits["noRequestsSent"] == 0 {
		panic("[ " + redText("!") + " ] [ " + redText("No Requests Sent Ratelimit Is Empty (Please set it to a very high value if you want to \"disable\" it).") + " ]")
	}
	getFingerprintRequestRL = proxy.Ratelimits["noRequestsSent"]
	fmt.Println("[" + redText("+") + "] [ " + redText("No Requests Sent Ratelimit") + " ] > " + fmt.Sprint(getFingerprintRequestRL))
	fmt.Println("[ " + redText("Loaded Proxy Config") + " ]")
	fmt.Println("")

	domains := configuration.Domains
	for i := 0; i < len(domains); i++ {

		domainName := domains[i].Name

		domainList = append(domainList, domainName)

		if watchedDomain == "" {
			watchedDomain = domainName
		}

		var cert tls.Certificate = tls.Certificate{}
		if !cloudflareMode {
			var certErr error = nil
			cert, certErr = tls.LoadX509KeyPair(domains[i].Certificate, domains[i].Key)
			if certErr != nil {
				panic("[ " + redText("!") + " ] [ " + redText("Error Loading Certificates: "+certErr.Error()) + " ]")
			}
		}

		fmt.Println("[" + redText("+") + "] [ " + redText("Name") + " ] > " + domains[i].Name)
		fmt.Println("[" + redText("+") + "] [ " + redText("Scheme") + " ] > " + domains[i].Scheme)
		fmt.Println("[" + redText("+") + "] [ " + redText("Backend") + " ] > " + domains[i].Backend)
		fmt.Println("[" + redText("+") + "] [ " + redText("Certificate") + " ] > " + domains[i].Certificate)
		fmt.Println("[" + redText("+") + "] [ " + redText("Key") + " ] > " + domains[i].Key)

		fmt.Println("[ " + redText("Loaded Domain Proxy") + " ]")

		customRules := []Rule{}
		ipInfo := false

		firewallRules := domains[i].FirewallRules
		for i := 0; i < len(firewallRules); i++ {

			mutex.Lock()
			if strings.Contains(firewallRules[i].Expression, "ip.country") || strings.Contains(firewallRules[i].Expression, "ip.asn") {
				ipInfo = true
			}
			f, err := gofilter.NewFilter(firewallRules[i].Expression)
			if err != nil {
				panic("[ " + redText("!") + " ] [ Error Loading Custom Firewalls: " + redText(err.Error()) + " ]")
			}
			customRules = append(customRules, Rule{
				Filter: f,
				Action: firewallRules[i].Action,
			})

			fmt.Println("[" + redText("+") + "] [ " + redText("Expression") + " ] > " + firewallRules[i].Expression)
			fmt.Println("[" + redText("+") + "] [ " + redText("Action") + " ] > " + firewallRules[i].Action)
			mutex.Unlock()
		}
		fmt.Println("[ " + redText("Loaded Custom Firewalls") + " ]")

		fmt.Println("[" + redText("+") + "] [ " + redText("Bypass Stage 1") + " ] > " + fmt.Sprint(domains[i].BypassStage1))
		fmt.Println("[" + redText("+") + "] [ " + redText("Bypass Stage 2") + " ] > " + fmt.Sprint(domains[i].BypassStage2))
		fmt.Println("[" + redText("+") + "] [ " + redText("Disable Bypass Stage 3") + " ] > " + fmt.Sprint(domains[i].DisableBypassStage3))
		fmt.Println("[" + redText("+") + "] [ " + redText("Disable Raw Stage 3") + " ] > " + fmt.Sprint(domains[i].DisableRawStage3))
		fmt.Println("[" + redText("+") + "] [ " + redText("Disable Bypass Stage 2") + " ] > " + fmt.Sprint(domains[i].DisableBypassStage2))
		fmt.Println("[" + redText("+") + "] [ " + redText("Disable Raw Stage 2") + " ] > " + fmt.Sprint(domains[i].DisableRawStage2))

		dProxy := httputil.NewSingleHostReverseProxy(&url.URL{
			Scheme: domains[i].Scheme,
			Host:   domains[i].Backend,
		})
		dProxy.Transport = &proxyRoundTripper{}

		domainsMap.Store(domainName, DomainSettings{
			name:             domainName,
			stage:            1,
			stageManuallySet: false,
			rawAttack:        false,
			bypassAttack:     false,
			lastLogs:         []string{},

			customRules: customRules,
			ipInfo:      ipInfo,

			domainProxy:        dProxy,
			domainCertificates: cert,
			domainWebhooks: WebhookSettings{
				Url:            domains[i].Webhook.Url,
				Name:           domains[i].Webhook.Name,
				Avatar:         domains[i].Webhook.Avatar,
				AttackStartMsg: domains[i].Webhook.AttackStartMsg,
				AttackStopMsg:  domains[i].Webhook.AttackStopMsg,
			},
			bypassStage1:        domains[i].BypassStage1,
			bypassStage2:        domains[i].BypassStage2,
			disableBypassStage3: domains[i].DisableBypassStage3,
			disableRawStage3:    domains[i].DisableRawStage3,
			disableBypassStage2: domains[i].DisableBypassStage2,
			disableRawStage2:    domains[i].DisableRawStage2,

			totalRequests:    0,
			bypassedRequests: 0,

			prevRequests: 0,
			prevBypassed: 0,

			requestsPerSecond:             0,
			requestsBypassedPerSecond:     0,
			peakRequestsPerSecond:         0,
			peakRequestsBypassedPerSecond: 0,
			RequestLogger:                 []RequestLog{},
		})
	}
	fmt.Println("[ " + redText("Loaded Domains") + " ]")
	fmt.Println("")

	var boltErr error
	boltDb, boltErr = bolt.Open("proxyCache.db", 0600, nil)
	if boltErr != nil {
		fmt.Println(boltErr)
		return
	}
	//defer boltDb.Close()

	boltDb.Update(func(tx *bolt.Tx) error {
		var boltErr error
		_, boltErr = tx.CreateBucketIfNotExists([]byte("countries"))
		if boltErr != nil {
			panic("[ " + redText("!") + " ] [ " + redText("Failed To Create Bucket") + " ] > " + boltErr.Error())
		}

		_, boltErr = tx.CreateBucketIfNotExists([]byte("asns"))
		if boltErr != nil {
			panic("[ " + redText("!") + " ] [ " + redText("Failed To Create Bucket") + " ] > " + boltErr.Error())
		}
		return nil
	})

	server := http.Server{}

	//Create http server to redirect to https
	httpServer := http.Server{}

	//Create https server to handle requests
	if cloudflareMode {
		server = http.Server{
			Addr: ":80",
			//Terminate Idle/Inactive connections
			IdleTimeout:       5 * time.Second,
			ReadTimeout:       5 * time.Second,
			WriteTimeout:      7 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
		}

		fmt.Println("[ Reverse Proxy ]: Started on " + server.Addr)
	} else {
		server = http.Server{
			Addr:      ":443",
			ConnState: cw.OnStateChange,
			//Terminate Idle/Inactive connections
			IdleTimeout:       5 * time.Second,
			ReadTimeout:       5 * time.Second,
			WriteTimeout:      7 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
			TLSConfig: &tls.Config{
				GetConfigForClient: getConfigForClient,
				GetCertificate:     GetCertificate,
			},
		}
		httpServer = http.Server{
			Addr:      ":80",
			ConnState: cw.OnStateChange,
			//Terminate Idel/Inactive connections
			IdleTimeout:       5 * time.Second,
			ReadTimeout:       5 * time.Second,
			WriteTimeout:      7 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
		}

		fmt.Println("[ Reverse Proxy ]: Started on " + server.Addr)

		//Redirect http connections to https
		httpServer.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			domainVal, ok := domainsMap.Load(r.Host)
			if !ok {
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprintf(w, "balooProxy: "+r.Host+" does not exist. If you are the owner please check your config.json if you believe this is a mistake")
				return
			}

			tempDomain := domainVal.(DomainSettings)
			tempDomain.totalRequests = tempDomain.totalRequests + 1

			domainsMap.Store(r.Host, tempDomain)

			http.Redirect(w, r, "https://"+r.Host+r.URL.Path+r.URL.RawQuery, http.StatusMovedPermanently)

		})
	}

	//Setting keepalive to false to better prevent ddos attacks from creating too many connections (play around with it. not sure if it's better on or off)
	server.SetKeepAlivesEnabled(false)

	//Handle requests
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		domainName := r.Host

		domainVal, ok := domainsMap.Load(r.Host)
		if !ok {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "balooProxy: "+r.Host+" does not exist. If you are the owner please check your config.json if you believe this is a mistake")
			return
		}

		tempDomain := domainVal.(DomainSettings)
		tempDomain.totalRequests++

		var ip string
		var tlsFp string
		var browser string
		var botFp string

		var fpCount int
		var ipCount int
		var ipCountCookie int

		if cloudflareMode {
			ip = r.Header.Get("Cf-Connecting-Ip")

			tlsFp = "Cloudflare"
			browser = "Cloudflare"
			botFp = ""
			fpCount = 0

			mutex.Lock()
			ipCount = accessIps[ip]
			ipCountCookie = accessIpsCookie[ip]
			mutex.Unlock()
		} else {
			ip = strings.Split(r.RemoteAddr, ":")[0]

			//Retrieve information about the client
			mutex.Lock()
			tlsFp = connections[r.RemoteAddr]
			browser = fingerprints[tlsFp]
			botFp = botFingerprints[tlsFp]

			fpCount = unkFps[tlsFp]
			ipCount = accessIps[ip]
			ipCountCookie = accessIpsCookie[ip]
			mutex.Unlock()
		}

		w.Header().Set("baloo-Proxy", "1.0")

		//Start the suspicious level where the stage currently is
		susLv := tempDomain.stage
		var RCE = []string{"..", ";", "SELECT FROM", "SELECT * FROM", "FROM", "VALUES", "DELETE FROM", "ONION", "union", "UNION", "DROP TABLE", "--", "INSERT INTO", "UPDATE `users` SET", "UPDATE settings SET", "UPDATE `settings` SET", "UPDATE users SET", "WHERE username", "or ", "WHERE id", "DROP TABLE", "0x50", "mid((select", "union(((((((", "concat(0x", "concat(", "OR ", "0x3c62723e3c62723e3c62723e", "0x3c696d67207372633d22", "+#1q%0AuNiOn all#qa%0A#%0AsEleCt", "unhex(hex(Concat(", "Table_schema,0x3e,", "0x00", "0x08", "0x09", "0x0a", "0x0d", "0x1a", "0x22", "0x25", "0x27", "0x5c", "0x5f", "%2F", "exec", "chmod", "chown", "eval", "shell_exec", "curl_multi_exec", "apache_setenv", "..", "passwd", "nc", "netcat", "curl", ";", ";--", "bash", "sh ", "echo", "|", "ping", "cat", "${IFS}", "$", ">", "{", "}", "%", "[", "]", "(", ")", "<", "wget"}
		decodedValue, err := url.QueryUnescape(r.URL.RawQuery)
		if err != nil {
			log.Fatal(err)
			return
		}
		for _, word := range RCE {
			if strings.Contains(strings.ToUpper(decodedValue), strings.ToUpper(word)) {
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprintf(w, "Blocked by baloo proxy, XSS or RCE attempt detected.")
				return
			}
		}

		//Ratelimit faster if client repeatedly fails the verification challenge (feel free to play around with the threshhold)
		if ipCountCookie > IPChallengeRequestRL {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "Blocked by BalooProxy.\nYou have been ratelimited. (R1)")
			domainsMap.Store(domainName, tempDomain)
			return
		}

		//Ratelimit spamming Ips (feel free to play around with the threshhold)
		if ipCount > IPRequestRL {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "Blocked by BalooProxy.\nYou have been ratelimited. (R2)")
			domainsMap.Store(domainName, tempDomain)
			return
		}

		//Ratelimit fingerprints that don't belong to major browsers
		if browser == "" {
			if fpCount > fingerprintRequestRL {
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprintf(w, "Blocked by BalooProxy.\nYou have been ratelimited. (R3)")
				domainsMap.Store(domainName, tempDomain)
				return
			}

			mutex.Lock()
			unkFps[tlsFp] = unkFps[tlsFp] + 1
			mutex.Unlock()
		}

		//Block user-specified fingerprints
		mutex.Lock()
		forbiddenFp := forbiddenFingerprints[tlsFp]
		mutex.Unlock()
		if forbiddenFp != "" {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "Blocked by BalooProxy.\nYour browser %s is not allowed.", forbiddenFp)
			domainsMap.Store(domainName, tempDomain)
			return
		}

		//Demonstration of how to use "susLv". Essentially allows you to challenge specific requests with a higher challenge

		ipInfoCountry := "N/A"
		ipInfoASN := "N/A"
		if tempDomain.ipInfo {
			ipInfoCountry, ipInfoASN = getIpInfo(ip)
		}

		requestVariables := gofilter.Message{
			"ip.src":                net.ParseIP(ip),
			"ip.country":            ipInfoCountry,
			"ip.asn":                ipInfoASN,
			"ip.engine":             browser,
			"ip.bot":                botFp,
			"ip.fingerprint":        tlsFp,
			"ip.http_requests":      ipCount,
			"ip.challenge_requests": ipCountCookie,

			"http.host":      r.Host,
			"http.version":   r.Proto,
			"http.method":    r.Method,
			"http.query":     r.URL.RawQuery,
			"http.path":      r.URL.Path,
			"http.UserAgent": strings.ToLower(r.UserAgent()),
			"http.cookie":    r.Header.Get("Cookie"),
			"http.headers":   fmt.Sprint(r.Header),

			"proxy.stage":         tempDomain.stage,
			"proxy.cloudflare":    cloudflareMode,
			"proxy.stage_locked":  tempDomain.stageManuallySet,
			"proxy.attack":        tempDomain.rawAttack,
			"proxy.bypass_attack": tempDomain.bypassAttack,
			"proxy.rps":           tempDomain.requestsPerSecond,
			"proxy.rpsAllowed":    tempDomain.requestsBypassedPerSecond,
		}

		susLv = evalFirewallRule(tempDomain, requestVariables, susLv)

		//Check if encryption-result is already "cached" to prevent load on reverse proxy
		mutex.Lock()
		encryptedIP := cacheIps[ip+fmt.Sprint(susLv)]
		mutex.Unlock()

		if encryptedIP == "" {
			hr, _, _ := time.Now().Clock()
			switch susLv {
			case 0:
				//whitelisted
			case 1:
				encryptedIP = encrypt(ip+tlsFp+fmt.Sprint(hr), CookieSecretKey)
			case 2:
				encryptedIP = encrypt(ip+tlsFp+fmt.Sprint(hr), JsSecretKey)
			case 3:
				encryptedIP = encrypt(ip+tlsFp+fmt.Sprint(hr), CaptchaSecretKey)
			default:
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprintf(w, "Blocked by BalooProxy.\nSuspicious request of level %d (base %d)", susLv, tempDomain.stage)
				domainsMap.Store(domainName, tempDomain)
				return
			}
			mutex.Lock()
			cacheIps[ip+fmt.Sprint(susLv)] = encryptedIP
			mutex.Unlock()
		}

		//Check if client provided correct verification result
		if !strings.Contains(r.Header.Get("Cookie"), fmt.Sprintf("__bProxy_v=%s", encryptedIP)) {

			mutex.Lock()
			accessIpsCookie[ip] = accessIpsCookie[ip] + 1
			mutex.Unlock()

			//Respond with verification challenge if client didnt provide correct result/none
			switch susLv {
			case 0:
				//This request is not to be challenged (whitelist)
			case 1:
				w.Header().Set("Set-Cookie", "_1__bProxy_v="+encryptedIP+"; SameSite=None; path=/; Secure")
				http.Redirect(w, r, r.URL.RequestURI(), http.StatusTemporaryRedirect)
				domainsMap.Store(domainName, tempDomain)
				return
			case 2:
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprintf(w, `<script>document.cookie = '_2__bProxy_v=%s; SameSite=None; path=/; Secure';window.location.reload();</script>`, encryptedIP)
				domainsMap.Store(domainName, tempDomain)
				return
			case 3:
				secretPart := encryptedIP[:6]
				publicPart := encryptedIP[6:]

				mutex.Lock()
				captchaData := cacheImgs[secretPart]
				mutex.Unlock()

				if captchaData == "" {
					captchaImg := image.NewRGBA(image.Rect(0, 0, 100, 37))
					addLabel(captchaImg, rand.Intn(90), rand.Intn(30), publicPart[:6], color.RGBA{255, 0, 0, 100})
					addLabel(captchaImg, 25, 18, secretPart, color.RGBA{61, 140, 64, 255})

					amplitude := 2.0
					period := float64(37) / 5.0
					displacement := func(x, y int) (int, int) {
						dx := amplitude * math.Sin(float64(y)/period)
						dy := amplitude * math.Sin(float64(x)/period)
						return x + int(dx), y + int(dy)
					}
					captchaImg = warpImg(captchaImg, displacement)

					var buf bytes.Buffer
					if err := png.Encode(&buf, captchaImg); err != nil {
						fmt.Fprintf(w, `BalooProxy Error: Failed to encode captcha: %s`, err)
						domainsMap.Store(domainName, tempDomain)
						return
					}
					data := buf.Bytes()

					captchaData = base64.StdEncoding.EncodeToString(data)

					mutex.Lock()
					cacheImgs[secretPart] = captchaData
					mutex.Unlock()
				}

				w.Header().Set("Content-Type", "text/html")

				fmt.Fprintf(w,
					`
					<style>body{background-color:#f5f5f5;font-family:Arial,sans-serif}.center{display:flex;align-items:center;justify-content:center;height:100vh}.box{background-color:#fff;border:1px solid #ddd;border-radius:4px;padding:20px;width:500px}canvas{display:block;margin:0 auto;max-width:100%%;width:100%%;height:auto}input[type=text]{width:100%%;padding:12px 20px;margin:8px 0;box-sizing:border-box;border:2px solid #ccc;border-radius:4px}button{width:100%%;background-color:#4caf50;color:#fff;padding:14px 20px;margin:8px 0;border:none;border-radius:4px;cursor:pointer}button:hover{background-color:#45a049}.box{background-color:#fff;border:1px solid #ddd;border-radius:4px;padding:20px;width:500px;transition:height .1s;position:block}.box *{transition:opacity .1s}.success{background-color:#dff0d8;border:1px solid #d6e9c6;border-radius:4px;color:#3c763d;padding:20px}.failure{background-color:#f0d8d8;border:1px solid #e9c6c6;border-radius:4px;color:#763c3c;padding:20px}.collapsible{background-color:#f5f5f5;color:#444;cursor:pointer;padding:18px;width:100%%;border:none;text-align:left;outline:0;font-size:15px}.collapsible:after{content:'\002B';color:#777;font-weight:700;float:right;margin-left:5px}.collapsible.active:after{content:"\2212"}.collapsible:hover{background-color:#e5e5e5}.collapsible-content{padding:0 18px;max-height:0;overflow:hidden;transition:max-height .2s ease-out;background-color:#f5f5f5}</style><div class=center id=center><div class=box id=box><h1>Enter the <b>green</b> text you see in the picture</h1><canvas height=37 id=image width=100></canvas><form onsubmit="return checkAnswer(event)"><input id=text maxlength=6 placeholder=Solution required> <button type=submit>Submit</button></form><div class=success id=successMessage style=display:none>Success! Redirecting ...</div><div class=failure id=failMessage style=display:none>Failed! Please try again.</div><button class=collapsible>Why am I seeing this page?</button><div class=collapsible-content><p>The website you are trying to visit needs to make sure that you are not a bot. This is a common security measure to protect websites from automated spam and abuse. By entering the characters you see in the picture, you are helping to verify that you are a real person.</div></div></div><script>let canvas=document.getElementById("image");
					let ctx = canvas.getContext("2d");
					var image = new Image();
					image.onload = function() {
						ctx.drawImage(image, (canvas.width-image.width)/2, (canvas.height-image.height)/2);
					};
					image.src = "data:image/png;base64,%s";
					function checkAnswer(event) {
						// Prevent the form from being submitted
						event.preventDefault();
						// Get the user's input
						var input = document.getElementById('text').value;

						document.cookie = '%s_3__bProxy_v='+input+'%s; SameSite=None; path=/; Secure';

						// Check if the input is correct
						fetch('https://' + location.hostname + '/_bProxy/verified').then(function(response) {
							return response.text();
						}).then(function(text) {
							if(text === 'verified') {
								// If the answer is correct, show the success message
								var successMessage = document.getElementById("successMessage");
								successMessage.style.display = "block";

								setInterval(function(){
									// Animate the collapse of the box
									var box = document.getElementById("box");
									var height = box.offsetHeight;
									var collapse = setInterval(function() {
										height -= 20;
										box.style.height = height + "px";
										// Reduce the opacity of the child elements as the box collapses
										var elements = box.children;
										//successMessage.remove()
										for(var i = 0; i < elements.length; i++) {
											elements[i].style.opacity = 0
										}
										if(height <= 0) {
											// Set the height of the box to 0 after the collapse is complete
											box.style.height = "0";
											// Stop the collapse animation
											box.remove()
											clearInterval(collapse);
											location.reload();
										}
									}, 20);	
								}, 1000)
							} else {
								var failMessage = document.getElementById('failMessage');
								failMessage.style.display = 'block';
								setInterval(function() {
									location.reload()
								}, 1000)
							}
						}).catch(function(err){
							var failMessage = document.getElementById('failMessage');
							failMessage.style.display = 'block';
							setInterval(function() {
								location.reload()
							}, 1000)
						})
					}
					// Add JavaScript to toggle the visibility of the collapsible content
					var coll = document.getElementsByClassName("collapsible");
					var i;
					for(i = 0; i < coll.length; i++) {
						coll[i].addEventListener("click", function() {
							this.classList.toggle("active");
							var content = this.nextElementSibling;
							if(content.style.maxHeight) {
								content.style.maxHeight = null;
							} else {
								content.style.maxHeight = content.scrollHeight + "px";
							}
						});
					}</script>
					`, captchaData, ip, publicPart)
				domainsMap.Store(domainName, tempDomain)
				return
			default:
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprintf(w, "Blocked by BalooProxy.\nSuspicious request of level %d (base %d)", susLv, tempDomain.stage)
				domainsMap.Store(domainName, tempDomain)
				return
			}
		}

		//Access logs of clients that passed the challenge
		if browser != "" || botFp != "" {
			access := "[ " + redText(time.Now().Format("15:04:05")) + " ] > \033[35m" + ip + "\033[0m - \033[32m" + browser + botFp + "\033[0m - " + redText(r.UserAgent()) + " - " + redText(r.RequestURI)
			tempDomain = addLogs(access, tempDomain)
			mutex.Lock()
			accessIps[ip] = accessIps[ip] + 1
			mutex.Unlock()
		} else {
			access := "[ " + redText(time.Now().Format("15:04:05")) + " ] > \033[35m" + ip + "\033[0m - \033[31mUNK (" + tlsFp + ")\033[0m - " + redText(r.UserAgent()) + " - " + redText(r.RequestURI)
			tempDomain = addLogs(access, tempDomain)
			mutex.Lock()
			accessIps[ip] = accessIps[ip] + 1
			mutex.Unlock()
		}

		tempDomain.bypassedRequests++

		//Reserved proxy-paths
		switch r.URL.Path {
		case "/_bProxy/stats":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "Total Requests: %s\nBypassed Requests: %s\nTotal R/s: %s\nBypassed R/s: %s\nActive Connections: %s", fmt.Sprint(tempDomain.totalRequests), fmt.Sprint(tempDomain.bypassedRequests), fmt.Sprint(tempDomain.requestsPerSecond), fmt.Sprint(tempDomain.requestsBypassedPerSecond), fmt.Sprint(cw.Count()))
			domainsMap.Store(domainName, tempDomain)
			return
		case "/_bProxy/fingerprint":
			w.Header().Set("Content-Type", "text/plain")
			mutex.Lock()
			fmt.Fprintf(w, "IP: "+ip+"\nASN: "+fmt.Sprint(ipInfoASN)+"\nCountry: "+ipInfoCountry+"\nIP Requests: "+fmt.Sprint(ipCount)+"\nIP Challenge Requests: "+fmt.Sprint(accessIpsCookie[ip])+"\nFingerprint: "+tlsFp+"\nBrowser: "+browser+botFp)
			mutex.Unlock()
			domainsMap.Store(domainName, tempDomain)
			return
		case "/_bProxy/verified":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "verified")
			domainsMap.Store(domainName, tempDomain)
			return
		//Do not remove or modify this. It is required by the license
		case "/_bProxy/credits":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "BalooProxy; Lightweight http reverse-proxy https://github.com/41Baloo/balooProxy. Protected by GNU GENERAL PUBLIC LICENSE Version 2, June 1991")
			domainsMap.Store(domainName, tempDomain)
			return
		}

		domainsMap.Store(domainName, tempDomain)

		tempDomain.domainProxy.ServeHTTP(w, r)
	})

	//Start ssh based monitor
	go serverMonitor()

	if cloudflareMode {
		cloudflareErr := server.ListenAndServe()
		if cloudflareErr != nil {
			panic("[" + redText("!") + "] [ " + redText("Error Starting Cloudflare Server: "+cloudflareErr.Error()) + " ]")
		}
	} else {
		//Start http server
		go func() {
			serverErr := httpServer.ListenAndServe()
			if serverErr != nil {
				panic("[" + redText("!") + "] [ " + redText("Error Starting Server: "+serverErr.Error()) + " ]")
			}
		}()

		//Start https server (server.crt and server.key have to be your own ssl certificates)
		tlsErr := server.ListenAndServeTLS("", "")
		if tlsErr != nil {
			panic("[" + redText("!") + "] [ " + redText("Error Starting TLS Server: "+tlsErr.Error()) + " ]")
		}
	}
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

		//We can ratelimit so extremely here because normal browsers will send actual webrequests instead of only establishing connections
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

func GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domainVal, ok := domainsMap.Load(clientHello.ServerName)
	if ok {
		tempDomain := domainVal.(DomainSettings)
		return &tempDomain.domainCertificates, nil
	}
	return nil, nil
}

func (rt *proxyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {

	//Define 5 second timeout
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{
				Timeout: 5 * time.Second,
			}).DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	//Use inbuild RoundTrip
	resp, err := transport.RoundTrip(req)

	//Connection to backend failed. Display error message
	if err != nil {
		errStrs := strings.Split(err.Error(), " ")
		errMsg := ""
		for _, str := range errStrs {
			if !strings.Contains(str, ".") && !strings.Contains(str, "/") {
				errMsg += str + " "
			}
		}
		errPage := `<!DOCTYPE html><title>Error: ` + errMsg + `</title><style>body{font-family:'Helvetica Neue',sans-serif;color:#333;margin:0;padding:0}.container{display:flex;align-items:center;justify-content:center;height:100vh;background:#fafafa}.error-box{width:600px;padding:20px;background:#fff;border-radius:5px;box-shadow:0 2px 4px rgba(0,0,0,.1)}.error-box h1{font-size:36px;margin-bottom:20px}.error-box p{font-size:16px;line-height:1.5;margin-bottom:20px}.error-box p.description{font-style:italic;color:#666}.error-box a{display:inline-block;padding:10px 20px;background:#00b8d4;color:#fff;border-radius:5px;text-decoration:none;font-size:16px}</style><div class=container><div class=error-box><h1>Error: ` + errMsg + `</h1><p>Sorry, the backend returned an error. That's all we know.</p><a onclick=location.reload()>Reload page</a></div></div>`
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(strings.NewReader(errPage)),
		}, nil
	}

	//Connection was successfull, got bad response tho
	if resp.StatusCode >= 500 {
		errPage := `<!DOCTYPE html><title>Error: ` + resp.Status + `</title><style>body{font-family:'Helvetica Neue',sans-serif;color:#333;margin:0;padding:0}.container{display:flex;align-items:center;justify-content:center;height:100vh;background:#fafafa}.error-box{width:600px;padding:20px;background:#fff;border-radius:5px;box-shadow:0 2px 4px rgba(0,0,0,.1)}.error-box h1{font-size:36px;margin-bottom:20px}.error-box p{font-size:16px;line-height:1.5;margin-bottom:20px}.error-box p.description{font-style:italic;color:#666}.error-box a{display:inline-block;padding:10px 20px;background:#00b8d4;color:#fff;border-radius:5px;text-decoration:none;font-size:16px}</style><div class=container><div class=error-box><h1>Error: ` + resp.Status + `</h1><p>Sorry, the backend returned an error. That's all we know.</p><a onclick=location.reload()>Reload page</a></div></div>`
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(strings.NewReader(errPage)),
		}, nil
	}

	return resp, nil
}

//FUNCTIONS

func serverMonitor() {
	printMutex.Lock()
	screen.Clear()
	screen.MoveTopLeft()
	printMutex.Unlock()
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for {
			if scanner.Scan() {

				printMutex.Lock()
				fmt.Println("\033[" + fmt.Sprint(13+maxLogs) + ";1H")
				fmt.Print("\033[K[ " + redText("Command") + " ]: \033[s")

				input := scanner.Text()
				details := strings.Split(input, " ")

				domainVal, ok := domainsMap.Load(watchedDomain)
				tempDomain := DomainSettings{}
				if ok {
					tempDomain = domainVal.(DomainSettings)
				}

				switch details[0] {
				case "stage":
					if !(len(details) > 1) {
						break
					}
					setStage, err := strconv.ParseInt(details[1], 0, 64)
					if err != nil {
						break
					}
					tempDomain.stage = int(setStage)
					if tempDomain.stage == 0 {
						tempDomain.stage = 1
						tempDomain.stageManuallySet = false
					} else {
						tempDomain.stageManuallySet = true
					}
					domainsMap.Store(watchedDomain, tempDomain)
				case "domain":
					if len(details) < 2 {
						watchedDomain = ""
					} else {
						watchedDomain = details[1]
					}

					screen.Clear()
					screen.MoveTopLeft()
					fmt.Println("[ " + redText("Loading") + " ] ...")
					fmt.Println("\033[" + fmt.Sprint(13+maxLogs) + ";1H")
					fmt.Print("[ " + redText("Command") + " ]: \033[s")
				default:
					screen.Clear()
					screen.MoveTopLeft()
					fmt.Println("\033[" + fmt.Sprint(13+maxLogs) + ";1H")
					fmt.Print("[ " + redText("Command") + " ]: \033[s")
				}
				printMutex.Unlock()
			}
		}
	}()
	printMutex.Lock()
	fmt.Println("\033[" + fmt.Sprint(12+maxLogs) + ";1H")
	fmt.Print("[ " + redText("Command") + " ]: \033[s")
	printMutex.Unlock()
	for {
		for i := 0; i < 120; i++ {
			printMutex.Lock()
			tempWidth, tempHeight, _ := term.GetSize(int(os.Stdout.Fd()))
			tWidth = tempWidth + 18
			if tempHeight != tHeight || tempWidth+18 != tWidth {
				tHeight = tempHeight
				screen.Clear()
				screen.MoveTopLeft()
				fmt.Println("\033[" + fmt.Sprint(13+maxLogs) + ";1H")
				fmt.Print("[ " + redText("Command") + " ]: \033[s")
			}
			clearStats(maxLogs)
			fmt.Print("\033[1;1H")

			domainsMap.Range(func(_, dInterface interface{}) bool {
				dValue := dInterface.(DomainSettings)

				dValue.requestsPerSecond = dValue.totalRequests - dValue.prevRequests
				dValue.requestsBypassedPerSecond = dValue.bypassedRequests - dValue.prevBypassed

				dValue.prevRequests = dValue.totalRequests
				dValue.prevBypassed = dValue.bypassedRequests

				if !dValue.stageManuallySet || dValue.bypassAttack {

					if dValue.bypassAttack {
						if dValue.requestsPerSecond > dValue.peakRequestsPerSecond {
							dValue.peakRequestsPerSecond = dValue.requestsPerSecond
						}
						if dValue.requestsBypassedPerSecond > dValue.peakRequestsBypassedPerSecond {
							dValue.peakRequestsBypassedPerSecond = dValue.requestsBypassedPerSecond
						}
						dValue.RequestLogger = append(dValue.RequestLogger, RequestLog{
							Time:    time.Now(),
							Allowed: dValue.requestsBypassedPerSecond,
							Total:   dValue.requestsPerSecond,
						})
					}

					if dValue.stage == 1 && dValue.requestsBypassedPerSecond > dValue.bypassStage1 && !dValue.bypassAttack {
						dValue.bypassAttack = true
						dValue.stage = 2
						dValue.peakRequestsPerSecond = dValue.requestsPerSecond
						dValue.peakRequestsBypassedPerSecond = dValue.requestsBypassedPerSecond
						dValue.RequestLogger = append(dValue.RequestLogger, RequestLog{
							Time:    time.Now(),
							Allowed: dValue.requestsBypassedPerSecond,
							Total:   dValue.requestsPerSecond,
						})
						go sendWebhook(dValue, int(0))
					} else if dValue.stage == 2 && dValue.requestsBypassedPerSecond > dValue.bypassStage2 {
						dValue.stage = 3
					} else if dValue.stage == 3 && dValue.requestsBypassedPerSecond < dValue.disableBypassStage3 && dValue.requestsPerSecond < dValue.disableRawStage3 {
						dValue.stage = 2
					} else if dValue.stage == 2 && dValue.requestsBypassedPerSecond < dValue.disableBypassStage2 && dValue.requestsPerSecond < dValue.disableRawStage2 && dValue.bypassAttack {
						dValue.bypassAttack = false
						dValue.stage = 1
						go sendWebhook(dValue, int(1))
					}
				}

				domainsMap.Store(dValue.name, dValue)
				return true
			})

			result, err := cpu.Percent(0, false)
			if err != nil {
				fmt.Println("[" + redText("+") + "] [ " + redText("Cpu Usage") + " ] > [ " + redText(err.Error()) + " ]")
			} else if len(result) > 0 {
				fmt.Println("[" + redText("+") + "] [ " + redText("Cpu Usage") + " ] > [ " + redText(fmt.Sprintf("%.2f", result[0])) + " ]")
			} else {
				fmt.Println("[" + redText("+") + "] [ " + redText("Cpu Usage") + " ] > [ " + redText("100.00 ( Speculated )") + " ]")
			}

			fmt.Println("")

			dVal, ok := domainsMap.Load(watchedDomain)
			if !ok {
				if watchedDomain != "" {
					fmt.Println("[" + redText("!") + "] [ " + redText("Domain \""+watchedDomain+"\" Not Found") + " ]")
					fmt.Println("")
				}
				fmt.Println("[" + redText("Available Domains") + "]")
				counter := 0
				for _, dName := range domainList {
					if counter < maxLogs {
						fmt.Println("[" + redText("+") + "] [ " + redText(dName) + " ]")
						counter++
					}
				}
			} else {

				tempDomain := dVal.(DomainSettings)

				fmt.Println("[" + redText("+") + "] [ " + redText("Domain") + " ] > [ " + redText(watchedDomain) + " ]")
				fmt.Println("[" + redText("+") + "] [ " + redText("Stage") + " ] > [ " + redText(fmt.Sprint(tempDomain.stage)) + " ]")
				fmt.Println("[" + redText("+") + "] [ " + redText("Stage Locked") + " ] > [ " + redText(fmt.Sprint(tempDomain.stageManuallySet)) + " ]")
				fmt.Println("")
				fmt.Println("[" + redText("+") + "] [ " + redText("Total") + " ] > [ " + redText(fmt.Sprint(tempDomain.requestsPerSecond)+" r/s") + " ]")
				fmt.Println("[" + redText("+") + "] [ " + redText("Bypassed") + " ] > [ " + redText(fmt.Sprint(tempDomain.requestsBypassedPerSecond)+" r/s") + " ]")
				fmt.Println("[" + redText("+") + "] [ " + redText("Connections") + " ] > [ " + redText(fmt.Sprint(cw.Count())) + " ]")

				fmt.Println("")
				fmt.Println("[ " + redText("Latest Logs") + " ]")

				for _, log := range tempDomain.lastLogs {
					if len(log)+4 > tWidth {
						fmt.Println("[" + redText("+") + "] " + log[:len(log)-(len(log)+4-tWidth)] + " ...\033[0m")
					} else {
						fmt.Println("[" + redText("+") + "] " + log)
					}
				}
			}

			moveInputLine()

			printMutex.Unlock()
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
		for cacheImg := range cacheImgs {
			delete(cacheImgs, cacheImg)
		}
		mutex.Unlock()
	}
}

// Helper function to keep writing at the same line
func moveInputLine() {
	fmt.Println("\033[" + fmt.Sprint(13+maxLogs) + ";1H")
	fmt.Print("[ " + redText("Command") + " ]: \033[u\033[s")
}

func clearStats(length int) {
	fmt.Print("\033[s")
	for j := 1; j < 9+length; j++ {
		fmt.Println("\033[" + fmt.Sprint(j) + ";1H\033[K")
	}
}

// Helper function to make text red
func redText(input string) string {
	return "\033[31m" + input + "\033[0m"
}

func evalFirewallRule(currDomain DomainSettings, variables gofilter.Message, susLv int) int {
	result := susLv
	for _, rule := range currDomain.customRules {
		if rule.Filter.Apply(variables) {
			//Check if we want to statically set susLv or add to it
			switch rule.Action[:1] {
			case "+":
				var actionInt int
				_, err := fmt.Sscan(rule.Action[1:], &actionInt)
				if err != nil {
					fmt.Println("[ " + redText("!") + " ] [ " + redText("Error Evaluating Rule: "+err.Error()) + " ]")
					//Dont change anything on error. We dont want issues in production
				} else {
					result = result + actionInt
					//fmt.Println("[" + redText("+") + "] [ Matched Rule ] > " + fmt.Sprint(result))
				}
			case "-":
				var actionInt int
				_, err := fmt.Sscan(rule.Action[1:], &actionInt)
				if err != nil {
					fmt.Println("[ " + redText("!") + " ] [ " + redText("Error Evaluating Rule: "+err.Error()) + " ]")
					//Dont change anything on error. We dont want issues in production
				} else {
					result = result - actionInt
					//fmt.Println("[" + redText("+") + "] [ Matched Rule ] > " + fmt.Sprint(result))
				}
			default:
				var actionInt int
				_, err := fmt.Sscan(rule.Action, &actionInt)
				if err != nil {
					fmt.Println("[ " + redText("!") + " ] [ " + redText("Error Evaluating Rule: "+err.Error()) + " ]")
				} else {
					result = actionInt
					return result
				}
			}
		}
	}
	return result
}

func (cw *ConnectionWatcher) Count() int {
	return int(atomic.LoadInt64(&cw.n))
}

func (cw *ConnectionWatcher) Add(c int64) {
	atomic.AddInt64(&cw.n, c)
}

func encrypt(input string, key string) string {
	hasher := sha1.New()
	hasher.Write([]byte(input + key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func addLabel(img *image.RGBA, x, y int, label string, color color.RGBA) {
	point := fixed.Point26_6{X: fixed.I(x), Y: fixed.I(y)}

	d := &font.Drawer{
		Dst:  img,
		Src:  image.NewUniform(color),
		Face: basicfont.Face7x13,
		Dot:  point,
	}
	d.DrawString(label)
}

func addLogs(entry string, domain DomainSettings) DomainSettings {

	printMutex.Lock()
	if len(domain.lastLogs) > maxLogs {
		domain.lastLogs = domain.lastLogs[1:]
		domain.lastLogs = append(domain.lastLogs, entry)

		for i, log := range domain.lastLogs {
			if len(log)+4 > tWidth {
				fmt.Print("\033[" + fmt.Sprint(12+i) + ";1H\033[K[" + redText("!") + "] " + log[:len(log)-(len(log)+4-tWidth)] + " ...\033[0m\n")
			} else {
				fmt.Print("\033[" + fmt.Sprint(12+i) + ";1H\033[K[" + redText("!") + "] " + log + "\n")
			}
		}
		moveInputLine()
		printMutex.Unlock()
		return domain
	}
	domain.lastLogs = append(domain.lastLogs, entry)
	if domain.name == watchedDomain {
		if len(entry)+4 > tWidth {
			fmt.Print("\033[" + fmt.Sprint((11 + len(domain.lastLogs))) + ";1H\033[K[" + redText("-") + "] " + entry[:len(entry)-(len(entry)+4-tWidth)] + " ...\033[0m\n")
		} else {
			fmt.Print("\033[" + fmt.Sprint((11 + len(domain.lastLogs))) + ";1H\033[K[" + redText("-") + "] " + entry + "\n")
		}
	}
	moveInputLine()
	printMutex.Unlock()
	return domain
}

func sendWebhook(domain DomainSettings, notificationType int) {

	if domain.domainWebhooks.Url == "" {
		return
	}

	webhookContent := Webhook{}

	switch notificationType {
	case 0:
		description := strings.ReplaceAll(domain.domainWebhooks.AttackStartMsg, "{{domain.name}}", domain.name)
		webhookContent = Webhook{
			Content:  "",
			Username: domain.domainWebhooks.Name,
			Avatar:   domain.domainWebhooks.Avatar,
			Embeds: []WebhookEmbed{
				{
					Title:       "DDoS Alert",
					Description: description,
					Color:       5814783,
					Fields: []WebhookField{
						{
							Name:  "Total requests per second",
							Value: "```\n" + fmt.Sprint(domain.requestsPerSecond) + "\n```",
						},
						{
							Name:  "Allowed requests per second",
							Value: "```\n" + fmt.Sprint(domain.requestsBypassedPerSecond) + "\n```",
						},
					},
				},
			},
		}
	case 1:

		description := strings.ReplaceAll(domain.domainWebhooks.AttackStopMsg, "{{domain.name}}", domain.name)

		allowedData := "["
		totalData := "["

		requests := domain.RequestLogger

		for _, request := range requests {
			currTime := request.Time.Format("2006-01-02 15:04:05")
			allowedData += `{"x": "` + currTime + `", "y": ` + fmt.Sprint(request.Allowed) + `},`
			totalData += `{"x": "` + currTime + `", "y": ` + fmt.Sprint(request.Total) + ` },`
		}

		allowedData = strings.TrimSuffix(allowedData, ",")
		totalData = strings.TrimSuffix(totalData, ",")

		allowedData += "]"
		totalData += "]"

		//panic(allowedData + "\n" + totalData)

		//imageUrl := "https://quickchart.io/chart?c=" + url.QueryEscape("{\"type\": \"line\",\"data\": {\"datasets\": [{\"label\": \"Allowed\",\"backgroundColor\": \"rgba(35, 159, 217, 0.5)\",\"borderColor\": \"rgb(35, 159, 217)\",\"fill\": false,\"data\": "+allowedData+"},{\"label\": \"Total\",\"backgroundColor\": \"rgba(100, 100, 100, 0.5)\",\"borderColor\": \"rgb(100, 100, 100)\",\"fill\": false,\"data\": "+totalData+"}]},\"options\": {\"responsive\": true,\"title\": {\"display\": true,\"text\": \"Attack Details\"},\"scales\": {\"xAxes\": [{\"type\": \"time\",\"display\": true,\"scaleLabel\": {\"display\": true,\"labelString\": \"Time\"},\"ticks\": {\"major\": {\"enabled\": true}}}],\"yAxes\": [{\"display\": true,\"scaleLabel\": {\"display\": true,\"labelString\": \"Requests\"}}]}}}")

		jsonStr := `{"chart":{"type":"line","data":{"datasets":[{"label":"Allowed","backgroundColor":"rgba(35, 159, 217, 0.5)","borderColor":"rgb(35, 159, 217)","fill":false,"data":` + allowedData + `},{"label":"Total","backgroundColor":"rgba(100, 100, 100, 0.5)","borderColor":"rgb(100, 100, 100)","fill":false,"data":` + totalData + `}]},"options":{"responsive":true,"title":{"display":true,"text":"Attack Details"},"scales":{"xAxes":[{"type":"time","display":true,"scaleLabel":{"display":true,"labelString":"Time"},"ticks":{"major":{"enabled":true}}}],"yAxes":[{"display":true,"scaleLabel":{"display":true,"labelString":"Requests"}}]}}}}`

		client := &http.Client{}
		req, reqErr := http.NewRequest("POST", "https://quickchart.io/chart/create", bytes.NewBuffer([]byte(jsonStr)))
		if reqErr != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, respErr := client.Do(req)
		defer resp.Body.Close()
		if respErr != nil {
			return
		}

		body, bodyErr := io.ReadAll(resp.Body)
		if bodyErr != nil {
			return
		}

		var chartResp QuickchartResponse
		json.Unmarshal(body, &chartResp)

		webhookContent = Webhook{
			Content:  "",
			Username: domain.domainWebhooks.Name,
			Avatar:   domain.domainWebhooks.Avatar,
			Embeds: []WebhookEmbed{
				{
					Title:       "DDoS Alert",
					Description: description,
					Color:       5814783,
					Fields: []WebhookField{
						{
							Name:  "Peak total requests per second",
							Value: "```\n" + fmt.Sprint(domain.peakRequestsPerSecond) + "\n```",
						},
						{
							Name:  "Peak allowed requests per second",
							Value: "```\n" + fmt.Sprint(domain.peakRequestsBypassedPerSecond) + "\n```",
						},
					},
					Image: WebhookImage{
						Url: chartResp.Url,
					},
				},
			},
		}

		domain.peakRequestsPerSecond = 0
		domain.peakRequestsBypassedPerSecond = 0
		domain.RequestLogger = []RequestLog{}

		domainsMap.Store(domain.name, domain)
	}

	webhookPayload, err := json.Marshal(webhookContent)
	if err != nil {
		return
	}

	req, err := http.NewRequest("POST", domain.domainWebhooks.Url, bytes.NewBuffer(webhookPayload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	client.Do(req)
}

func warpImg(src image.Image, displacement func(x, y int) (int, int)) *image.RGBA {
	bounds := src.Bounds()
	minX := bounds.Min.X
	minY := bounds.Min.Y
	maxX := bounds.Max.X
	maxY := bounds.Max.Y

	dst := image.NewRGBA(image.Rect(minX, minY, maxX, maxY))
	for x := minX; x < maxX; x++ {
		for y := minY; y < maxY; y++ {
			dx, dy := displacement(x, y)
			if dx < minX || dx > maxX || dy < minY || dy > maxY {
				continue
			}
			dst.Set(x, y, src.At(dx, dy))
		}
	}
	return dst
}

func getIpInfo(IP string) (country string, asn string) {

	var ipCountry []byte
	var ipAsn []byte

	boltDb.View(func(tx *bolt.Tx) error {
		countries := tx.Bucket([]byte("countries"))
		asns := tx.Bucket([]byte("asns"))

		ipCountry = countries.Get([]byte(IP))
		ipAsn = asns.Get([]byte(IP))

		return nil
	})

	//Check if result already in database
	if string(ipCountry) != "" {
		return string(ipCountry), string(ipAsn)
	}

	//If not, request it
	resp, err := http.Get("http://apimon.de/ip/" + IP)
	if err != nil {
		return "UNK", "UNK"
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "UNK", "UNK"
	}

	var data IpInfo
	err = json.Unmarshal(body, &data)
	if err != nil {
		return "UNK", "UNK"
	}

	//Write to database for future usage
	updateErr := boltDb.Update(func(tx *bolt.Tx) error {
		countries := tx.Bucket([]byte("countries"))
		asns := tx.Bucket([]byte("asns"))

		// Store a value.
		err = countries.Put([]byte(IP), []byte(data.Country.Code))
		if err != nil {
			return err
		}
		err = asns.Put([]byte(IP), []byte(data.AS.Num))
		if err != nil {
			return err
		}

		return nil
	})
	if updateErr != nil {
		return "UNK", "UNK"
	}

	return data.Country.Code, data.AS.Num
}

//STRUCTS

type Configuration struct {
	Proxy   Proxy          `json:"proxy"`
	Domains []Domain       `json:"domains"`
	Rules   []FirewallRule `json:"rules"`
}

type Proxy struct {
	Cloudflare   bool              `json:"cloudflare"`
	MaxLogLength int               `json:"maxLogLength"`
	Secrets      map[string]string `json:"secrets"`
	Ratelimits   map[string]int    `json:"ratelimits"`
}

type Domains struct {
	Domains []Domain `json:"domains"`
}

type Domain struct {
	Name                string          `json:"name"`
	Backend             string          `json:"backend"`
	Scheme              string          `json:"scheme"`
	Certificate         string          `json:"certificate"`
	Key                 string          `json:"key"`
	Webhook             WebhookSettings `json:"webhook"`
	FirewallRules       []FirewallRule  `json:"rules"`
	BypassStage1        int             `json:"bypassStage1"`
	BypassStage2        int             `json:"bypassStage2"`
	DisableBypassStage3 int             `json:"disableBypassStage3"`
	DisableRawStage3    int             `json:"disableRawStage3"`
	DisableBypassStage2 int             `json:"disableBypassStage2"`
	DisableRawStage2    int             `json:"disableRawStage2"`
}

type FirewallRules struct {
	Rules []FirewallRule `json:"rules"`
}

type FirewallRule struct {
	Expression string `json:"expression"`
	Action     string `json:"action"`
}

type Rule struct {
	Filter *gofilter.Filter
	Action string
}

type WebhookSettings struct {
	Url            string `json:"url"`
	Name           string `json:"name"`
	Avatar         string `json:"avatar"`
	AttackStartMsg string `json:"attack_start_msg"`
	AttackStopMsg  string `json:"attack_stop_msg"`
}

type Webhook struct {
	Content  string         `json:"content"`
	Embeds   []WebhookEmbed `json:"embeds"`
	Username string         `json:"username"`
	Avatar   string         `json:"avatar_url"`
}

type WebhookEmbed struct {
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Color       int            `json:"color"`
	Fields      []WebhookField `json:"fields"`
	Image       WebhookImage   `json:"image"`
}

type WebhookField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type WebhookImage struct {
	Url string `json:"url"`
}

type QuickchartResponse struct {
	Success string `json:"success"`
	Url     string `json:"url"`
}

type RequestLog struct {
	Time    time.Time
	Allowed int
	Total   int
}

type DomainSettings struct {
	name             string
	stage            int
	stageManuallySet bool
	rawAttack        bool
	bypassAttack     bool
	lastLogs         []string

	customRules []Rule
	ipInfo      bool

	domainProxy        *httputil.ReverseProxy
	domainCertificates tls.Certificate
	domainWebhooks     WebhookSettings

	bypassStage1        int
	bypassStage2        int
	disableBypassStage3 int
	disableRawStage3    int
	disableBypassStage2 int
	disableRawStage2    int

	totalRequests    int
	bypassedRequests int

	prevRequests int
	prevBypassed int

	requestsPerSecond             int
	requestsBypassedPerSecond     int
	peakRequestsPerSecond         int
	peakRequestsBypassedPerSecond int
	RequestLogger                 []RequestLog
}

type proxyRoundTripper struct {
}

type IpInfo struct {
	Country struct {
		Code string `json:"alpha2_code"`
	} `json:"country"`
	AS struct {
		Num string `json:"number"`
	} `json:"as"`
}

type ConnectionWatcher struct {
	n int64
}
