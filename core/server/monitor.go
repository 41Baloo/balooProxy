package server

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http/httputil"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2/middleware/adaptor"
	"github.com/kor44/gofilter"
	"github.com/shirou/gopsutil/cpu"
	"golang.org/x/term"

	"goProxy/core/domains"
	"goProxy/core/firewall"
	"goProxy/core/pnc"
	"goProxy/core/proxy"
	"goProxy/core/utils"
)

var (
	PrintMutex = &sync.Mutex{}
	helpMode   = false
)

func Monitor() {

	defer pnc.PanicHndl()

	PrintMutex.Lock()
	fmt.Print("\033[2J")
	PrintMutex.Unlock()

	//Responsible for handeling user-commands
	go commands()

	//Responsible for clearing outdated cache and data
	go clearProxyCache()

	//Responsible for clearing outdated websitecache
	go clearOutdatedCache()

	//Responsible for generating non-bruteforable secrets
	go generateOTPSecrets()

	PrintMutex.Lock()
	fmt.Println("\033[" + fmt.Sprint(11+proxy.MaxLogLength) + ";1H")
	fmt.Print("[ " + utils.RedText("Command") + " ]: \033[s")
	PrintMutex.Unlock()
	for {
		PrintMutex.Lock()
		tempWidth, tempHeight, _ := term.GetSize(int(os.Stdout.Fd()))
		proxy.TWidth = tempWidth + 18
		if tempHeight != proxy.THeight || tempWidth+18 != proxy.TWidth {
			proxy.THeight = tempHeight

			pHeight := tempHeight - 15
			if pHeight < 0 {
				proxy.MaxLogLength = 0
			} else {
				proxy.MaxLogLength = pHeight
			}

			fmt.Print("\033[2J")
			fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
			fmt.Print("[ " + utils.RedText("Command") + " ]: \033[s")
		}
		utils.ClearScreen(proxy.MaxLogLength)
		fmt.Print("\033[1;1H")

		firewall.Mutex.Lock()
		for name, data := range domains.DomainsData {
			checkAttack(name, data)
		}
		firewall.Mutex.Unlock()

		printStats()

		PrintMutex.Unlock()
		time.Sleep(1 * time.Second)
	}
}

// Only run this inside of a locked thread to avoid false reports
func checkAttack(domainName string, domainData domains.DomainData) {

	if domainName == "debug" {
		return
	}

	domainData.RequestsPerSecond = domainData.TotalRequests - domainData.PrevRequests
	domainData.RequestsBypassedPerSecond = domainData.BypassedRequests - domainData.PrevBypassed

	domainData.PrevRequests = domainData.TotalRequests
	domainData.PrevBypassed = domainData.BypassedRequests

	if !domainData.StageManuallySet || (domainData.BufferCooldown > 0) {

		// Log requests if a bypassing or raw attack is ongoing
		if domainData.BufferCooldown > 0 {
			if domainData.RequestsPerSecond > domainData.PeakRequestsPerSecond {
				domainData.PeakRequestsPerSecond = domainData.RequestsPerSecond
			}
			if domainData.RequestsBypassedPerSecond > domainData.PeakRequestsBypassedPerSecond {
				domainData.PeakRequestsBypassedPerSecond = domainData.RequestsBypassedPerSecond
			}
			domainData.RequestLogger = append(domainData.RequestLogger, domains.RequestLog{
				Time:     time.Now(),
				Allowed:  domainData.RequestsBypassedPerSecond,
				Total:    domainData.RequestsPerSecond,
				CpuUsage: proxy.CpuUsage,
			})
		}

		settingQuery, _ := domains.DomainsMap.Load(domainName)
		domainSettings := settingQuery.(domains.DomainSettings)

		if !domainData.BypassAttack && !domainData.RawAttack && (domainData.BufferCooldown > 0) {
			domainData.BufferCooldown--

			if domainData.BufferCooldown == 0 {
				utils.AddLogs("Attack Ending Webhook Sent", "debug")
				go utils.SendWebhook(domainData, domainSettings, int(1))
				domainData.PeakRequestsPerSecond = 0
				domainData.PeakRequestsBypassedPerSecond = 0
				domainData.RequestLogger = []domains.RequestLog{}
			}
		}

		switch domainData.Stage {
		case 1:
			// A Bypassing Attack Started
			if domainData.RequestsBypassedPerSecond > domainSettings.BypassStage1 && !domainData.BypassAttack {
				utils.AddLogs("Bypassing Attack Started", "debug")
				domainData.BypassAttack = true
				domainData.Stage = 2
				if domainData.BufferCooldown == 0 {
					domainData.PeakRequestsPerSecond = domainData.RequestsPerSecond
					domainData.PeakRequestsBypassedPerSecond = domainData.RequestsBypassedPerSecond
					domainData.RequestLogger = append(domainData.RequestLogger, domains.RequestLog{
						Time:     time.Now(),
						Allowed:  domainData.RequestsBypassedPerSecond,
						Total:    domainData.RequestsPerSecond,
						CpuUsage: proxy.CpuUsage,
					})
					go utils.SendWebhook(domainData, domainSettings, int(0))
				}
				// Start/Set cooldown
				domainData.BufferCooldown = 10
			}
		case 2:
			// Stage 2 is getting bypassed
			if domainData.RequestsBypassedPerSecond > domainSettings.BypassStage2 {
				domainData.Stage = 3

				// Stage 2 is no longer getting bypassed
			} else if domainData.RequestsBypassedPerSecond < domainSettings.DisableBypassStage2 && domainData.RequestsPerSecond < domainSettings.DisableRawStage2 && domainData.BypassAttack {
				utils.AddLogs("Bypassing Attack Ended", "debug")
				domainData.BypassAttack = false
				domainData.RawAttack = false
				domainData.Stage = 1
			}
		case 3:
			// Stage 3 is no longer getting bypassed
			if domainData.RequestsBypassedPerSecond < domainSettings.DisableBypassStage3 && domainData.RequestsPerSecond < domainSettings.DisableRawStage3 {
				domainData.Stage = 2
			}
		}

		// An attack that didnt bypass was started
		if domainData.RequestsPerSecond > domainSettings.DisableRawStage2 && !domainData.RawAttack && !domainData.BypassAttack {
			utils.AddLogs("Raw Attack Started", "debug")
			domainData.RawAttack = true

			if domainData.BufferCooldown == 0 {
				domainData.PeakRequestsPerSecond = domainData.RequestsPerSecond
				domainData.PeakRequestsBypassedPerSecond = domainData.RequestsBypassedPerSecond
				domainData.RequestLogger = append(domainData.RequestLogger, domains.RequestLog{
					Time:     time.Now(),
					Allowed:  domainData.RequestsBypassedPerSecond,
					Total:    domainData.RequestsPerSecond,
					CpuUsage: proxy.CpuUsage,
				})
				go utils.SendWebhook(domainData, domainSettings, int(0))
			}

			//Set/Start cooldown
			domainData.BufferCooldown = 10
		} else if domainData.RequestsPerSecond < domainSettings.DisableRawStage2 && domainData.RawAttack && !domainData.BypassAttack {
			utils.AddLogs("Raw Attack Ended", "debug")
			domainData.RawAttack = false
		}

	}

	domains.DomainsData[domainName] = domainData
}

func printStats() {

	proxy.LastSecondTime = time.Now()
	proxy.CurrHour, _, _ = proxy.LastSecondTime.Clock()

	result, err := cpu.Percent(0, false)
	if err != nil {
		proxy.CpuUsage = "ERR"
		fmt.Println("[" + utils.RedText("+") + "] [ " + utils.RedText("Cpu Usage") + " ] > [ " + utils.RedText(err.Error()) + " ]")
	} else if len(result) > 0 {
		proxy.CpuUsage = fmt.Sprintf("%.2f", result[0])
		fmt.Println("[" + utils.RedText("+") + "] [ " + utils.RedText("Cpu Usage") + " ] > [ " + utils.RedText(proxy.CpuUsage) + " ]")
	} else {
		proxy.CpuUsage = "ERR_S0"
		fmt.Println("[" + utils.RedText("+") + "] [ " + utils.RedText("Cpu Usage") + " ] > [ " + utils.RedText("100.00 ( Speculated )") + " ]")
	}

	//Not printed yet but calculated ram usage in %

	var ramStats runtime.MemStats
	runtime.ReadMemStats(&ramStats)

	// Calculate the current memory usage in percentage
	proxy.RamUsage = fmt.Sprintf("%.2f", float64(ramStats.Alloc)/float64(ramStats.Sys)*100)

	fmt.Println("")

	firewall.Mutex.Lock()
	domainData := domains.DomainsData[proxy.WatchedDomain]
	firewall.Mutex.Unlock()

	if domainData.Stage == 0 && proxy.WatchedDomain != "debug" {
		if proxy.WatchedDomain != "" {
			fmt.Println("[" + utils.RedText("!") + "] [ " + utils.RedText("Domain \""+proxy.WatchedDomain+"\" Not Found") + " ]")
			fmt.Println("")
		}
		fmt.Println("[" + utils.RedText("Available Domains") + "]")
		counter := 0
		for _, dName := range domains.Domains {
			if counter < proxy.MaxLogLength {
				fmt.Println("[" + utils.RedText("+") + "] [ " + utils.RedText(dName) + " ]")
				counter++
			}
		}
	} else if helpMode {
		fmt.Println("[" + utils.RedText("Available Commands") + "]")
		fmt.Println("")
		fmt.Println("[" + utils.RedText("+") + "] [ " + utils.RedText("help") + " ]: " + utils.RedText("Displays all available commands. More detailed information can be found at ") + "https://github.com/41Baloo/balooProxy#commands")
		fmt.Println("[" + utils.RedText("+") + "] [ " + utils.RedText("stage") + " ]: " + utils.RedText("Usage: ") + "stage [number] " + utils.RedText("Locks the stage to the specified number. Use ") + "stage 0 " + utils.RedText("to unlock the stage"))
		fmt.Println("[" + utils.RedText("+") + "] [ " + utils.RedText("domain") + " ]: " + utils.RedText("Usage: ") + "domain [name] " + utils.RedText("Switch between your domains. Type only ") + "domain " + utils.RedText("to list all available domains"))
		fmt.Println("[" + utils.RedText("+") + "] [ " + utils.RedText("add") + " ]: " + utils.RedText("Usage: ") + "add " + utils.RedText("Starts a dialouge to add another domain to the proxy"))
		fmt.Println("[" + utils.RedText("+") + "] [ " + utils.RedText("rtlogs") + " ]: " + utils.RedText("Usage: ") + "rtlogs " + utils.RedText("Toggels 'Real-Time-Logs' on and off. It is suggested to keep off"))
		fmt.Println("[" + utils.RedText("+") + "] [ " + utils.RedText("clrlogs") + " ]: " + utils.RedText("Usage: ") + "clrlogs " + utils.RedText("Clears all logs for the current domain"))
		fmt.Println("[" + utils.RedText("+") + "] [ " + utils.RedText("cachemode") + " ]: " + utils.RedText("Usage: ") + "cachemode " + utils.RedText("Toggels whether or not the proxy tries to cache on and off"))
		fmt.Println("[" + utils.RedText("+") + "] [ " + utils.RedText("delcache") + " ]: " + utils.RedText("Usage: ") + "delcache " + utils.RedText("Clears the cache for the current domain"))
		fmt.Println("[" + utils.RedText("+") + "] [ " + utils.RedText("reload") + " ]: " + utils.RedText("Usage: ") + "reload " + utils.RedText("Reload your proxy in order for changes in your ") + "config.json " + utils.RedText("to take effect"))
	} else {

		fmt.Println("[" + utils.RedText("+") + "] [ " + utils.RedText("Domain") + " ] > [ " + utils.RedText(proxy.WatchedDomain) + " ]")
		fmt.Println("[" + utils.RedText("+") + "] [ " + utils.RedText("Stage") + " ] > [ " + utils.RedText(fmt.Sprint(domainData.Stage)) + " ]")
		fmt.Println("[" + utils.RedText("+") + "] [ " + utils.RedText("Stage Locked") + " ] > [ " + utils.RedText(fmt.Sprint(domainData.StageManuallySet)) + " ]")
		fmt.Println("")
		fmt.Println("[" + utils.RedText("+") + "] [ " + utils.RedText("Total") + " ] > [ " + utils.RedText(fmt.Sprint(domainData.RequestsPerSecond)+" r/s") + " ]")
		fmt.Println("[" + utils.RedText("+") + "] [ " + utils.RedText("Bypassed") + " ] > [ " + utils.RedText(fmt.Sprint(domainData.RequestsBypassedPerSecond)+" r/s") + " ]")

		fmt.Println("")
		fmt.Println("[ " + utils.RedText("Latest Logs") + " ]")

		for _, log := range domainData.LastLogs {
			if len(log)+4 > proxy.TWidth {
				fmt.Println("[" + utils.RedText("+") + "] " + log[:len(log)-(len(log)+4-proxy.TWidth)] + " ...\033[0m")
			} else {
				fmt.Println("[" + utils.RedText("+") + "] " + log)
			}
		}
	}

	utils.MoveInputLine()
}

func commands() {

	defer pnc.PanicHndl()

	scanner := bufio.NewScanner(os.Stdin)
	for {
		if scanner.Scan() {

			PrintMutex.Lock()
			fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
			fmt.Print("\033[K[ " + utils.RedText("Command") + " ]: \033[s")

			input := scanner.Text()
			details := strings.Split(input, " ")

			firewall.Mutex.Lock()
			domainData := domains.DomainsData[proxy.WatchedDomain]
			firewall.Mutex.Unlock()
			helpMode = false

			switch details[0] {
			case "stage":

				if domainData.Stage == 0 {
					break
				}
				if !(len(details) > 1) {
					break
				}
				setStage, err := strconv.ParseInt(details[1], 0, 64)
				if err != nil {
					break
				}
				stage := int(setStage)
				if stage == 0 {
					domainData.Stage = 1
					domainData.StageManuallySet = false

					firewall.Mutex.Lock()
					domains.DomainsData[proxy.WatchedDomain] = domainData
					firewall.Mutex.Unlock()
				} else {
					domainData.Stage = stage
					domainData.StageManuallySet = true

					firewall.Mutex.Lock()
					domains.DomainsData[proxy.WatchedDomain] = domainData
					firewall.Mutex.Unlock()
				}
			case "domain":
				if len(details) < 2 {
					proxy.WatchedDomain = ""
				} else {
					proxy.WatchedDomain = details[1]
				}

				fmt.Print("\033[2J")
				fmt.Println("[ " + utils.RedText("Loading") + " ] ...")
				fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
				fmt.Print("[ " + utils.RedText("Command") + " ]: \033[s")
			case "add":
				fmt.Print("\033[2J")
				utils.AddDomain()
				fmt.Print("\033[2J")
				fmt.Println("[ " + utils.RedText("Loading") + " ] ...")
				fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
				fmt.Print("[ " + utils.RedText("Command") + " ]: \033[s")
				reloadConfig()
			case "rtlogs":
				fmt.Print("\033[2J")
				if proxy.RealTimeLogs {
					proxy.RealTimeLogs = false
					fmt.Println("[ " + utils.RedText("Turning Real Time Logs Off") + " ] ...")
				} else {
					proxy.RealTimeLogs = true
					fmt.Println("[ " + utils.RedText("Turning Real Time Logs On") + " ] ...")
				}
				fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
				fmt.Print("[ " + utils.RedText("Command") + " ]: \033[s")
			case "clrlogs":
				fmt.Print("\033[2J")
				if proxy.WatchedDomain == "" {
					for _, domain := range domains.Domains {
						firewall.Mutex.Lock()
						utils.ClearLogs(domain)
						firewall.Mutex.Unlock()
					}
					fmt.Println("[ " + utils.RedText("Clearing Logs All Domains ") + " ] ...")
				} else {
					firewall.Mutex.Lock()
					utils.ClearLogs(proxy.WatchedDomain)
					firewall.Mutex.Unlock()
					fmt.Println("[ " + utils.RedText("Clearing Logs For "+proxy.WatchedDomain) + " ] ...")
				}
				fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
				fmt.Print("[ " + utils.RedText("Command") + " ]: \033[s")
			case "delcache":
				fmt.Print("\033[2J")
				fmt.Println("[ " + utils.RedText("Clearing Cache For "+proxy.WatchedDomain) + " ] ...")
				clearCache()
				fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
				fmt.Print("[ " + utils.RedText("Command") + " ]: \033[s")
			case "reload":
				fmt.Print("\033[2J")
				fmt.Println("[ " + utils.RedText("Reloading Proxy") + " ] ...")
				reloadConfig()
				fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
				fmt.Print("[ " + utils.RedText("Command") + " ]: \033[s")
			case "help":
				helpMode = true
				fmt.Print("\033[2J")
				fmt.Println("[ " + utils.RedText("Loading") + " ] ...")
				fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
				fmt.Print("[ " + utils.RedText("Command") + " ]: \033[s")
			case "cachemode":
				fmt.Print("\033[2J")
				if proxy.CacheEnabled {
					proxy.CacheEnabled = false
					fmt.Println("[ " + utils.RedText("Turning Caching Off") + " ] ...")
				} else {
					proxy.CacheEnabled = true
					fmt.Println("[ " + utils.RedText("Turning Caching On") + " ] ...")
				}
				fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
				fmt.Print("[ " + utils.RedText("Command") + " ]: \033[s")
			default:
				fmt.Print("\033[2J")
				fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
				fmt.Print("[ " + utils.RedText("Command") + " ]: \033[s")
			}
			PrintMutex.Unlock()
		}
	}
}

// This would ideally be in package config, however import cycles seem to not allow this.
func reloadConfig() {

	domains.Domains = []string{}

	file, err := os.Open("config.json")
	if err != nil {
		panic(err)
	}
	defer file.Close()
	json.NewDecoder(file).Decode(&domains.Config)

	proxy.Cloudflare = domains.Config.Proxy.Cloudflare

	proxy.CookieSecret = domains.Config.Proxy.Secrets["cookie"]
	proxy.JSSecret = domains.Config.Proxy.Secrets["javascript"]
	proxy.CaptchaSecret = domains.Config.Proxy.Secrets["captcha"]

	// Check if the Proxy Timeout Config has been set otherwise use default values

	if domains.Config.Proxy.Timeout.Idle != 0 {
		proxy.IdleTimeout = domains.Config.Proxy.Timeout.Idle
		proxy.IdleTimeoutDuration = time.Duration(proxy.IdleTimeout).Abs() * time.Second
	}

	if domains.Config.Proxy.Timeout.Read != 0 {
		proxy.ReadTimeout = domains.Config.Proxy.Timeout.Read
		proxy.ReadTimeoutDuration = time.Duration(proxy.ReadTimeout).Abs() * time.Second
	}

	if domains.Config.Proxy.Timeout.ReadHeader != 0 {
		proxy.ReadHeaderTimeout = domains.Config.Proxy.Timeout.ReadHeader
		proxy.ReadHeaderTimeoutDuration = time.Duration(proxy.ReadHeaderTimeout).Abs() * time.Second
	}

	if domains.Config.Proxy.Timeout.Write != 0 {
		proxy.WriteTimeout = domains.Config.Proxy.Timeout.Write
		proxy.WriteTimeoutDuration = time.Duration(proxy.WriteTimeout).Abs() * time.Second
	}

	proxy.IPRatelimit = domains.Config.Proxy.Ratelimits["requests"]
	proxy.FPRatelimit = domains.Config.Proxy.Ratelimits["unknownFingerprint"]
	proxy.FailChallengeRatelimit = domains.Config.Proxy.Ratelimits["challengeFailures"]
	proxy.FailRequestRatelimit = domains.Config.Proxy.Ratelimits["noRequestsSent"]

	for i, domain := range domains.Config.Domains {
		domains.Domains = append(domains.Domains, domain.Name)

		ipInfo := false
		firewallRules := []domains.Rule{}
		rawFirewallRules := domains.Config.Domains[i].FirewallRules
		for _, fwRule := range domains.Config.Domains[i].FirewallRules {

			if strings.Contains(fwRule.Expression, "ip.country") || strings.Contains(fwRule.Expression, "ip.asn") {
				ipInfo = true
			}
			rule, err := gofilter.NewFilter(fwRule.Expression)
			if err != nil {
				panic("[ " + utils.RedText("!") + " ] [ Error Loading Custom Firewall Rules: " + utils.RedText(err.Error()) + " ]")
			}

			firewallRules = append(firewallRules, domains.Rule{
				Filter: rule,
				Action: fwRule.Action,
			})
		}

		cacheRules := []domains.Rule{}
		rawCacheRules := domains.Config.Domains[i].CacheRules
		for _, caRule := range domains.Config.Domains[i].CacheRules {

			rule, err := gofilter.NewFilter(caRule.Expression)
			if err != nil {
				panic("[ " + utils.RedText("!") + " ] [ Error Loading Custom Cache Rules: " + utils.RedText(err.Error()) + " ]")
			}

			cacheRules = append(cacheRules, domains.Rule{
				Filter: rule,
				Action: caRule.Action,
			})
		}

		dProxy := httputil.NewSingleHostReverseProxy(&url.URL{
			Scheme: domain.Scheme,
			Host:   domain.Backend,
		})
		dProxy.Transport = &RoundTripper{}

		dProxyHandler := adaptor.HTTPHandler(dProxy)

		var cert tls.Certificate = tls.Certificate{}
		if !proxy.Cloudflare {
			var certErr error
			cert, certErr = tls.LoadX509KeyPair(domain.Certificate, domain.Key)
			if certErr != nil {
				panic("[ " + utils.RedText("!") + " ] [ " + utils.RedText("Error Loading Certificates: "+certErr.Error()) + " ]")
			}
		}

		domains.DomainsMap.Store(domain.Name, domains.DomainSettings{
			Name: domain.Name,

			CustomRules:    firewallRules,
			IPInfo:         ipInfo,
			RawCustomRules: rawFirewallRules,

			CacheRules:    cacheRules,
			RawCacheRules: rawCacheRules,

			DomainProxy:        dProxyHandler,
			DomainCertificates: cert,
			DomainWebhooks: domains.WebhookSettings{
				URL:            domain.Webhook.URL,
				Name:           domain.Webhook.Name,
				Avatar:         domain.Webhook.Avatar,
				AttackStartMsg: domain.Webhook.AttackStartMsg,
				AttackStopMsg:  domain.Webhook.AttackStopMsg,
			},

			BypassStage1:        domain.BypassStage1,
			BypassStage2:        domain.BypassStage2,
			DisableBypassStage3: domain.DisableBypassStage3,
			DisableRawStage3:    domain.DisableRawStage3,
			DisableBypassStage2: domain.DisableBypassStage2,
			DisableRawStage2:    domain.DisableRawStage2,
		})

		firewall.Mutex.Lock()
		domains.DomainsData[domain.Name] = domains.DomainData{
			Stage:            1,
			StageManuallySet: false,
			RawAttack:        false,
			BypassAttack:     false,
			LastLogs:         []string{},

			TotalRequests:    0,
			BypassedRequests: 0,

			PrevRequests: 0,
			PrevBypassed: 0,

			RequestsPerSecond:             0,
			RequestsBypassedPerSecond:     0,
			PeakRequestsPerSecond:         0,
			PeakRequestsBypassedPerSecond: 0,
			RequestLogger:                 []domains.RequestLog{},
		}
		firewall.Mutex.Unlock()
	}

	proxy.WatchedDomain = domains.Domains[0]
}

func clearProxyCache() {

	defer pnc.PanicHndl()

	for {
		//Clear logs and maps every 2 minutes. (I know this is a lazy way to do it, tho for now it seems to be the most efficient and fast way to go about it)
		firewall.Mutex.Lock()
		for tcpRequest := range firewall.TcpRequests {
			delete(firewall.TcpRequests, tcpRequest)
		}
		for unk := range firewall.UnkFps {
			delete(firewall.UnkFps, unk)
		}
		for ip := range firewall.AccessIps {
			delete(firewall.AccessIps, ip)
		}
		for ipCookie := range firewall.AccessIpsCookie {
			delete(firewall.AccessIpsCookie, ipCookie)
		}

		proxyCpuUsage, pcuErr := strconv.ParseFloat(proxy.CpuUsage, 32)
		if pcuErr != nil {
			proxyCpuUsage = 0
		}

		utils.AddLogs("Calculated CPU To Be "+fmt.Sprint(proxyCpuUsage), "debug")

		proxyMemUsage, pmuErr := strconv.ParseFloat(proxy.RamUsage, 32)
		if pmuErr != nil {
			proxyMemUsage = 0
		}

		utils.AddLogs("Calculated Memory To Be "+fmt.Sprint(proxyMemUsage), "debug")

		// Only clear if proxy isnt under attack / memory is running out
		if (proxyCpuUsage < 15 && proxyMemUsage > 25) || proxyMemUsage > 95 {
			firewall.CacheIps.Range(func(key, value any) bool {
				firewall.CacheIps.Delete(key)
				return true
			})
			utils.AddLogs("Cleared Cached IPs", "debug")
		} else {
			utils.AddLogs("Did Not Clear Cached IPs", "debug")
		}
		// Same for here
		imgCachelen := 0
		firewall.CacheImgs.Range(func(key, value any) bool {
			imgCachelen++
			return true
		})
		if (proxyCpuUsage < 15 && proxyMemUsage > 25) || proxyMemUsage > 95 {
			firewall.CacheImgs.Range(func(key, value any) bool {
				firewall.CacheImgs.Delete(key)
				return true
			})
			utils.AddLogs("Cleared Cached Captchas", "debug")
		} else {
			utils.AddLogs("Did Not Clear Cached Captchas", "debug")
		}
		firewall.Mutex.Unlock()
		time.Sleep(2 * time.Minute)
	}
}

func clearCache() {
	domains.DomainsCache.Range(func(key, value any) bool {
		cacheResp := value.(domains.CacheResponse)
		if cacheResp.Domain == proxy.WatchedDomain {
			domains.DomainsCache.Delete(key)
		}
		return true
	})
}

func clearOutdatedCache() {

	defer pnc.PanicHndl()

	for {
		currTime := int(time.Now().Unix())
		domains.DomainsCache.Range(func(key, value any) bool {
			cacheResp := value.(domains.CacheResponse)
			if cacheResp.Timestamp < currTime {
				domains.DomainsCache.Delete(key)
			}
			return true
		})
		reloadConfig()

		firewall.Mutex.Lock()
		utils.AddLogs("Cleared Outdated Cache", "debug")
		firewall.Mutex.Unlock()

		time.Sleep(5 * time.Hour)
	}
}

func generateOTPSecrets() {

	defer pnc.PanicHndl()

	//You can change this to use hours as the hash key, to make it even more secure against offline bruteforcing, however, if you use multiple servers make sure they all start within the same timeframe, e.g.
	//Server1 starts at 23:59:50, Server2 starts at 00:00:01. In this case the keys are mismatched and clients would have to solve challenges again whenever they access a different server than before.
	//To avoid this and help you, this function runs every minute, reducing this offset to only 1 minute maximum of mismatch per day
	//This has now been changed to an hour, for better performance

	for {

		currTime := time.Now()
		currDate := currTime.Format("2006-01-02")

		proxy.CookieOTP = utils.EncryptSha(proxy.CookieSecret, currDate)
		proxy.JSOTP = utils.EncryptSha(proxy.JSSecret, currDate)
		proxy.CaptchaOTP = utils.EncryptSha(proxy.CaptchaSecret, currDate)

		firewall.Mutex.Lock()
		utils.AddLogs("Generated OTP Secrets", "debug")
		firewall.Mutex.Unlock()

		time.Sleep(1 * time.Hour)
	}
}
