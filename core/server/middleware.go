package server

import (
	"bytes"
	"encoding/base64"
	"goProxy/core/api"
	"goProxy/core/domains"
	"goProxy/core/firewall"
	"goProxy/core/proxy"
	"goProxy/core/utils"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/kor44/gofilter"
)


func generateRandomString() string {
	const digits = "0123456789"
	const letters = "abcdefghijklmnopqrstuvwxyz"

	// Initialiser le générateur de nombres aléatoires
	rand.Seed(time.Now().UnixNano())

	// Générer les parties de la chaîne
	numbers := make([]byte, 9)
	lettersPart := make([]byte, 2)

	for i := 0; i < 9; i++ {
		numbers[i] = digits[rand.Intn(len(digits))]
	}

	for i := 0; i < 2; i++ {
		lettersPart[i] = letters[rand.Intn(len(letters))]
	}

	// Retourner la chaîne formatée
	return fmt.Sprintf("mh-%s-%s", string(numbers), string(lettersPart))
}

func SendResponse(str string, buffer *bytes.Buffer, writer http.ResponseWriter) {
	buffer.WriteString(str)
	writer.Write(buffer.Bytes())
}


func ServeHTMLFile(writer http.ResponseWriter, filePath string, replacements map[string]string) {
    // Charger le fichier HTML depuis le disque
    htmlContent, err := ioutil.ReadFile(filePath)
    if err != nil {
        http.Error(writer, "Failed to load HTML file", http.StatusInternalServerError)
        return
    }

    // Remplacer les variables dans le contenu HTML
    modifiedContent := string(htmlContent)
    for key, value := range replacements {
        placeholder := fmt.Sprintf("{{%s}}", key)
        modifiedContent = strings.ReplaceAll(modifiedContent, placeholder, value)
    }

	placeholder := fmt.Sprintf("{{%s}}", "reference")
	modifiedContent = strings.ReplaceAll(modifiedContent, placeholder, generateRandomString())
    // Écrire le contenu modifié dans la réponse HTTP
    writer.Header().Set("Content-Type", "text/html")
    writer.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0") // Prévenir la mise en cache
    writer.Write([]byte(modifiedContent))
}


func Middleware(writer http.ResponseWriter, request *http.Request) {

	// defer pnc.PanicHndl() we wont do this during prod, to avoid overhead

	buffer := bufferPool.Get().(*bytes.Buffer)
	defer bufferPool.Put(buffer)
	buffer.Reset()

	domainName := request.Host

	firewall.Mutex.RLock()
	domainData, domainFound := domains.DomainsData[domainName]
	firewall.Mutex.RUnlock()

	if !domainFound {
		replacements := map[string]string{
			"status":  "404",
			"message": "Not found",
		}
	
		ServeHTMLFile(writer, "assets/html/error.html", replacements)
		return
	}

	var ip string
	var tlsFp string
	var browser string
	var botFp string

	var fpCount int
	var ipCount int
	var ipCountCookie int

	if domains.Config.Proxy.Cloudflare {

		ip = request.Header.Get("Cf-Connecting-Ip")

		tlsFp = "Cloudflare"
		browser = "Cloudflare"
		botFp = ""
		fpCount = 0

		firewall.Mutex.RLock()
		ipCount = firewall.AccessIps[ip]
		ipCountCookie = firewall.AccessIpsCookie[ip]
		firewall.Mutex.RUnlock()
	} else {
		ip = strings.Split(request.RemoteAddr, ":")[0]

		//Retrieve information about the client
		firewall.Mutex.RLock()
		tlsFp = firewall.Connections[request.RemoteAddr]
		fpCount = firewall.UnkFps[tlsFp]
		ipCount = firewall.AccessIps[ip]
		ipCountCookie = firewall.AccessIpsCookie[ip]
		firewall.Mutex.RUnlock()

		//Read-Only IMPORTANT: Must be put in mutex if you add the ability to change indexed fingerprints while program is running
		browser = firewall.KnownFingerprints[tlsFp]
		botFp = firewall.BotFingerprints[tlsFp]
	}

	firewall.Mutex.Lock()
	// Leaving this here for future reference. When the monitor thread that's supposed to prefill these maps lags
	//behind for some reason, this will be come really messy. The mutex will be locked and never unlocked again,
	//freezing the entire proxy
	/*_, temp_found := firewall.WindowAccessIps[proxy.Last10SecondTimestamp]
	if !temp_found {
		log.Printf("Attempting To Set %s, %d but timestamp hasn't been set yet ?!?", ip, proxy.Last10SecondTimestamp)
	}*/
	firewall.WindowAccessIps[proxy.Last10SecondTimestamp][ip]++
	domainData = domains.DomainsData[domainName]
	domainData.TotalRequests++
	domains.DomainsData[domainName] = domainData
	firewall.Mutex.Unlock()

	writer.Header().Set("baloo-Proxy", "1.5")

	//Start the suspicious level where the stage currently is
	susLv := domainData.Stage

	//Ratelimit faster if client repeatedly fails the verification challenge (feel free to play around with the threshhold)
	if ipCountCookie > proxy.FailChallengeRatelimit {
		replacements := map[string]string{
			"reason":  "Ratelimited (R1)",
		}
		ServeHTMLFile(writer, "assets/html/blocked.html", replacements)
		return
	}

	//Ratelimit spamming Ips (feel free to play around with the threshhold)
	if ipCount > proxy.IPRatelimit {
		replacements := map[string]string{
			"reason":  "Ratelimited (R2)",
		}
		ServeHTMLFile(writer, "assets/html/blocked.html", replacements)
		return
	}

	//Ratelimit fingerprints that don't belong to major browsers
	if browser == "" {
		if fpCount > proxy.FPRatelimit {
			replacements := map[string]string{
				"reason":  "Ratelimited (R3)",
			}
			ServeHTMLFile(writer, "assets/html/blocked.html", replacements)
			return
		}

		firewall.Mutex.Lock()
		firewall.WindowUnkFps[proxy.Last10SecondTimestamp][tlsFp]++
		firewall.Mutex.Unlock()
	}

	//Block user-specified fingerprints
	forbiddenFp := firewall.ForbiddenFingerprints[tlsFp]
	if forbiddenFp != "" {
		replacements := map[string]string{
			"reason":  "Your browser "+forbiddenFp+" is not allowed.",
		}
		ServeHTMLFile(writer, "assets/html/blocked.html", replacements)
		return
	}

	//Demonstration of how to use "susLv". Essentially allows you to challenge specific requests with a higher challenge

	//SyncMap because semi-readonly
	settingsQuery, _ := domains.DomainsMap.Load(domainName)
	domainSettings := settingsQuery.(domains.DomainSettings)

	reqUa := request.UserAgent()

	if len(domainSettings.CustomRules) != 0 {
		requestVariables := gofilter.Message{
			"ip.src":                net.ParseIP(ip),
			"ip.engine":             browser,
			"ip.bot":                botFp,
			"ip.fingerprint":        tlsFp,
			"ip.http_requests":      ipCount,
			"ip.challenge_requests": ipCountCookie,

			"http.host":       domainName,
			"http.version":    request.Proto,
			"http.method":     request.Method,
			"http.url":        request.RequestURI,
			"http.query":      request.URL.RawQuery,
			"http.path":       request.URL.Path,
			"http.user_agent": strings.ToLower(reqUa),
			"http.cookie":     request.Header.Get("Cookie"),

			"proxy.stage":         domainData.Stage,
			"proxy.cloudflare":    domains.Config.Proxy.Cloudflare,
			"proxy.stage_locked":  domainData.StageManuallySet,
			"proxy.attack":        domainData.RawAttack,
			"proxy.bypass_attack": domainData.BypassAttack,
			"proxy.rps":           domainData.RequestsPerSecond,
			"proxy.rps_allowed":   domainData.RequestsBypassedPerSecond,
		}

		susLv = firewall.EvalFirewallRule(domainSettings, requestVariables, susLv)
	}

	//Check if encryption-result is already "cached" to prevent load on reverse proxy
	encryptedIP := ""
	hashedEncryptedIP := ""
	susLvStr := utils.StageToString(susLv)
	accessKey := ip + tlsFp + reqUa + proxy.CurrHourStr
	encryptedCache, encryptedExists := firewall.CacheIps.Load(accessKey + susLvStr)

	if !encryptedExists {
		switch susLv {
		case 0:
			//whitelisted
		case 1:
			encryptedIP = utils.Encrypt(accessKey, proxy.CookieOTP)
		case 2:
			encryptedIP = utils.Encrypt(accessKey, proxy.JSOTP)
			hashedEncryptedIP = utils.EncryptSha(encryptedIP, "")
			firewall.CacheIps.Store(encryptedIP, hashedEncryptedIP)
		case 3:
			encryptedIP = utils.Encrypt(accessKey, proxy.CaptchaOTP)
		default:
			replacements := map[string]string{
				"reason":  "Suspicious request of level "+susLvStr+" (base "+strconv.Itoa(domainData.Stage)+")",
			}
			ServeHTMLFile(writer, "assets/html/blocked.html", replacements)
			return
		}
		firewall.CacheIps.Store(accessKey+susLvStr, encryptedIP)
	} else {
		encryptedIP = encryptedCache.(string)
		cachedHIP, foundCachedHIP := firewall.CacheIps.Load(encryptedIP)
		if foundCachedHIP {
			hashedEncryptedIP = cachedHIP.(string)
		}
	}

	//Check if client provided correct verification result
	if !strings.Contains(request.Header.Get("Cookie"), "__bProxy_v="+encryptedIP) {

		firewall.Mutex.Lock()
		firewall.WindowAccessIpsCookie[proxy.Last10SecondTimestamp][ip]++
		firewall.Mutex.Unlock()

		//Respond with verification challenge if client didnt provide correct result/none
		switch susLv {
		case 0:
			//This request is not to be challenged (whitelist)
		case 1:
			writer.Header().Set("Set-Cookie", "_1__bProxy_v="+encryptedIP+"; SameSite=Lax; path=/; Secure")
			http.Redirect(writer, request, request.URL.RequestURI(), http.StatusFound)
			return
		case 2:
			publicSalt := encryptedIP[:len(encryptedIP)-domainData.Stage2Difficulty]
			writer.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0") // Prevent special(ed) browsers from caching the challenge
			replacements := map[string]string{
				"publicSalt":  publicSalt,
				"hashedEncryptedIP": hashedEncryptedIP,
			}
			ServeHTMLFile(writer, "assets/html/stage2.html", replacements)
			return
		case 3:
			secretPart := encryptedIP[:6]
			publicPart := encryptedIP[6:]

			captchaData := ""
			maskData := ""
			captchaCache, captchaExists := firewall.CacheImgs.Load(secretPart)

			if !captchaExists {
				randomShift := rand.Intn(50) - 25
				captchaImg := image.NewRGBA(image.Rect(0, 0, 100, 37))
				randomColor := uint8(rand.Intn(255))
				utils.AddLabel(captchaImg, 0, 18, publicPart[6:], color.RGBA{61, 140, 64, 20})
				utils.AddLabel(captchaImg, rand.Intn(90), rand.Intn(30), publicPart[:6], color.RGBA{255, randomColor, randomColor, 100})
				utils.AddLabel(captchaImg, rand.Intn(25), rand.Intn(20)+10, secretPart, color.RGBA{61, 140, 64, 255})

				amplitude := float64(rand.Intn(10)+10) / 10.0
				period := float64(37) / 5.0
				displacement := func(x, y int) (int, int) {
					dx := amplitude * math.Sin(float64(y)/period)
					dy := amplitude * math.Sin(float64(x)/period)
					return x + int(dx), y + int(dy)
				}
				captchaImg = utils.WarpImg(captchaImg, displacement)

				maskImg := image.NewRGBA(captchaImg.Bounds())
				draw.Draw(maskImg, maskImg.Bounds(), image.Transparent, image.Point{}, draw.Src)

				numTriangles := rand.Intn(20) + 10

				blacklist := make(map[[2]int]bool) // We use this to keep track of already overwritten pixels.
				// it's slightly more performant to not do this but can lead to unsolvable captchas

				for i := 0; i < numTriangles; i++ {
					size := rand.Intn(5) + 10
					x := rand.Intn(captchaImg.Bounds().Dx() - size)
					y := rand.Intn(captchaImg.Bounds().Dy() - size)
					blacklist = utils.DrawTriangle(blacklist, captchaImg, maskImg, x, y, size, randomShift)
				}

				var captchaBuf, maskBuf bytes.Buffer
				if err := png.Encode(&captchaBuf, captchaImg); err != nil {
					replacements := map[string]string{
						"status":  "500",
						"message": "BalooProxy Error: Failed to encode captcha: "+err.Error(),
					}
				
					ServeHTMLFile(writer, "assets/html/error.html", replacements)
					return
				}
				if err := png.Encode(&maskBuf, maskImg); err != nil {
					replacements := map[string]string{
						"status":  "500",
						"message": "BalooProxy Error: Failed to encode captchaMask: "+err.Error(),
					}
				
					ServeHTMLFile(writer, "assets/html/error.html", replacements)
					return
				}

				captchaData = base64.StdEncoding.EncodeToString(captchaBuf.Bytes())
				maskData = base64.StdEncoding.EncodeToString(maskBuf.Bytes())

				firewall.CacheImgs.Store(secretPart, [2]string{captchaData, maskData})
			} else {
				captchaDataTmp := captchaCache.([2]string)
				captchaData = captchaDataTmp[0]
				maskData = captchaDataTmp[1]
			}


			writer.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0") // Prevent special(ed) browsers from caching the challenge

			replacements := map[string]string{
				"ip": ip,
				"captchaData": captchaData,
				"maskData": maskData,
			}
		
			ServeHTMLFile(writer, "assets/html/stage3.html", replacements)
			return
		default:
			replacements := map[string]string{
				"reason":  "Suspicious request of level "+susLvStr,
			}
			ServeHTMLFile(writer, "assets/html/blocked.html", replacements)
			return
		}
	}

	//Access logs of clients that passed the challenge
	firewall.Mutex.Lock()
	utils.AddLogs(domains.DomainLog{
		Time:      proxy.LastSecondTimeFormated,
		IP:        ip,
		BrowserFP: browser,
		BotFP:     botFp,
		TLSFP:     tlsFp,
		Useragent: reqUa,
		Path:      request.RequestURI,
	}, domainName)

	domainData = domains.DomainsData[domainName]
	domainData.BypassedRequests++
	domains.DomainsData[domainName] = domainData
	firewall.Mutex.Unlock()

	//Reserved proxy-paths

	switch request.URL.Path {
	case "/_bProxy/stats":
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("Stage: "+utils.StageToString(domainData.Stage)+"\nTotal Requests: "+strconv.Itoa(domainData.TotalRequests)+"\nBypassed Requests: "+strconv.Itoa(domainData.BypassedRequests)+"\nTotal R/s: "+strconv.Itoa(domainData.RequestsPerSecond)+"\nBypassed R/s: "+strconv.Itoa(domainData.RequestsBypassedPerSecond)+"\nProxy Fingerprint: "+proxy.Fingerprint, buffer, writer)
		return
	case "/_bProxy/fingerprint":
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("IP: "+ip+"\nIP Requests: "+strconv.Itoa(ipCount)+"\nIP Challenge Requests: "+strconv.Itoa(ipCountCookie)+"\nSusLV: "+strconv.Itoa(susLv)+"\nFingerprint: "+tlsFp+"\nBrowser: "+browser+botFp, buffer, writer)
		return
	case "/_bProxy/verified":
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("verified", buffer, writer)
		return
	case "/_bProxy/" + proxy.AdminSecret + "/api/v1":
		result := api.Process(writer, request, domainData)
		if result {
			return
		}

	//Do not remove or modify this. It is required by the license
	case "/_bProxy/credits":
		writer.Header().Set("Content-Type", "text/plain")
		SendResponse("BalooProxy; Lightweight http reverse-proxy https://github.com/41Baloo/balooProxy. Protected by GNU GENERAL PUBLIC LICENSE Version 2, June 1991", buffer, writer)
		return
	}

	if strings.HasPrefix(request.URL.Path, "/_bProxy/api/v2") {
		result := api.ProcessV2(writer, request)
		if result {
			return
		}
	}

	//Allow backend to read client information
	request.Header.Add("x-real-ip", ip)
	request.Header.Add("proxy-real-ip", ip)
	request.Header.Add("proxy-tls-fp", tlsFp)
	request.Header.Add("proxy-tls-name", browser+botFp)

	domainSettings.DomainProxy.ServeHTTP(writer, request)
}
