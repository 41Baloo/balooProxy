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

	"github.com/inancgumus/screen"
	"github.com/kor44/gofilter"
	"github.com/shirou/gopsutil/cpu"
	"golang.org/x/term"

	"goProxy/core/domains"
	"goProxy/core/firewall"
	"goProxy/core/proxy"
	"goProxy/core/utils"
)

var (
	PrintMutex = &sync.Mutex{}
)

func Monitor() {
	PrintMutex.Lock()
	screen.Clear()
	screen.MoveTopLeft()
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

			screen.Clear()
			screen.MoveTopLeft()
			fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
			fmt.Print("[ " + utils.RedText("Command") + " ]: \033[s")
		}
		utils.ClearScreen(proxy.MaxLogLength)
		fmt.Print("\033[1;1H")

		for name, data := range domains.DomainsData {
			firewall.Mutex.Lock()
			checkAttack(name, data)
			firewall.Mutex.Unlock()
		}

		printStats()

		PrintMutex.Unlock()
		time.Sleep(1 * time.Second)
	}
}

// Only run this inside of a locked thread to avoid false reports
func checkAttack(domainName string, domainData domains.DomainData) {

	domainData.RequestsPerSecond = domainData.TotalRequests - domainData.PrevRequests
	domainData.RequestsBypassedPerSecond = domainData.BypassedRequests - domainData.PrevBypassed

	domainData.PrevRequests = domainData.TotalRequests
	domainData.PrevBypassed = domainData.BypassedRequests

	if !domainData.StageManuallySet || domainData.BypassAttack {

		if domainData.BypassAttack {
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

		if domainData.Stage == 1 && domainData.RequestsBypassedPerSecond > domainSettings.BypassStage1 && !domainData.BypassAttack {
			domainData.BypassAttack = true
			domainData.Stage = 2
			domainData.PeakRequestsPerSecond = domainData.RequestsPerSecond
			domainData.PeakRequestsBypassedPerSecond = domainData.RequestsBypassedPerSecond
			domainData.RequestLogger = append(domainData.RequestLogger, domains.RequestLog{
				Time:     time.Now(),
				Allowed:  domainData.RequestsBypassedPerSecond,
				Total:    domainData.RequestsPerSecond,
				CpuUsage: proxy.CpuUsage,
			})
			go utils.SendWebhook(domainData, domainSettings, int(0))
		} else if domainData.Stage == 2 && domainData.RequestsBypassedPerSecond > domainSettings.BypassStage2 {
			domainData.Stage = 3
		} else if domainData.Stage == 3 && domainData.RequestsBypassedPerSecond < domainSettings.DisableBypassStage3 && domainData.RequestsPerSecond < domainSettings.DisableRawStage3 {
			domainData.Stage = 2
		} else if domainData.Stage == 2 && domainData.RequestsBypassedPerSecond < domainSettings.DisableBypassStage2 && domainData.RequestsPerSecond < domainSettings.DisableRawStage2 && domainData.BypassAttack {
			domainData.BypassAttack = false
			domainData.Stage = 1
			go utils.SendWebhook(domainData, domainSettings, int(1))
			domainData.PeakRequestsPerSecond = 0
			domainData.PeakRequestsBypassedPerSecond = 0
			domainData.RequestLogger = []domains.RequestLog{}
		}
	}

	domains.DomainsData[domainName] = domainData
}

func printStats() {
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

	if domainData.Stage == 0 {
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

				screen.Clear()
				screen.MoveTopLeft()
				fmt.Println("[ " + utils.RedText("Loading") + " ] ...")
				fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
				fmt.Print("[ " + utils.RedText("Command") + " ]: \033[s")
			case "add":
				screen.Clear()
				screen.MoveTopLeft()
				utils.AddDomain()
				screen.Clear()
				screen.MoveTopLeft()
				fmt.Println("[ " + utils.RedText("Loading") + " ] ...")
				fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
				fmt.Print("[ " + utils.RedText("Command") + " ]: \033[s")
				reloadConfig()
			case "rtlogs":
				screen.Clear()
				screen.MoveTopLeft()
				if proxy.RealTimeLogs {
					proxy.RealTimeLogs = false
					fmt.Println("[ " + utils.RedText("Turning Real Time Logs Off") + " ] ...")
				} else {
					proxy.RealTimeLogs = true
					fmt.Println("[ " + utils.RedText("Turning Real Time Logs On") + " ] ...")
				}
				fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
				fmt.Print("[ " + utils.RedText("Command") + " ]: \033[s")
			case "delcache":
				screen.Clear()
				screen.MoveTopLeft()
				fmt.Println("[ " + utils.RedText("Clearing Cache For "+proxy.WatchedDomain) + " ] ...")
				clearCache()
				fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
				fmt.Print("[ " + utils.RedText("Command") + " ]: \033[s")
			case "reload":
				screen.Clear()
				screen.MoveTopLeft()
				fmt.Println("[ " + utils.RedText("Reloading Proxy") + " ] ...")
				reloadConfig()
				fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
				fmt.Print("[ " + utils.RedText("Command") + " ]: \033[s")
			default:
				screen.Clear()
				screen.MoveTopLeft()
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

			CustomRules: firewallRules,
			IPInfo:      ipInfo,

			CacheRules: cacheRules,

			DomainProxy:        dProxy,
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
		firewall.CacheIps.Range(func(key, value any) bool {
			firewall.CacheIps.Delete(key)
			return true
		})
		firewall.CacheImgs.Range(func(key, value any) bool {
			firewall.CacheImgs.Delete(key)
			return true
		})
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
		time.Sleep(5 * time.Hour)
	}
}

func generateOTPSecrets() {

	//You can change this to use hours as the hash key, to make it even more secure against offline bruteforcing, however, if you use multiple servers make sure they all start within the same timeframe, e.g.
	//Server1 starts at 23:59:50, Server2 starts at 00:00:01. In this case the keys are mismatched and clients would have to solve challenges again whenever they access a different server than before.
	//To avoid this and help you, this function runs every minute, reducing this offset to only 1 minute maximum of mismatch per day

	for {
		currTime := time.Now()
		currDate := currTime.Format("2006-01-02")

		proxy.CookieOTP = utils.EncryptSha(proxy.CookieSecret, currDate)
		proxy.JSOTP = utils.EncryptSha(proxy.JSSecret, currDate)
		proxy.CaptchaOTP = utils.EncryptSha(proxy.CaptchaSecret, currDate)

		time.Sleep(1 * time.Minute)
	}
}
