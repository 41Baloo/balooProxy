package server

import (
	"bytes"
	"encoding/base64"
	"goProxy/core/api"
	"goProxy/core/domains"
	"goProxy/core/firewall"
	"goProxy/core/pnc"
	"goProxy/core/proxy"
	"goProxy/core/utils"
	"image"
	"image/color"
	"image/png"
	"math"
	"math/rand"
	"net"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/kor44/gofilter"
)

func Middleware(c *fiber.Ctx) error {

	defer pnc.PanicHndl()

	reqHeaders := c.GetReqHeaders()
	domainName := utils.SafeString(reqHeaders["Host"])
	firewall.Mutex.Lock()
	domainData := domains.DomainsData[domainName]
	firewall.Mutex.Unlock()

	if domainData.Stage == 0 {
		c.SendString("balooProxy: " + domainName + " does not exist. If you are the owner please check your config.json if you believe this is a mistake")
		return nil
	}

	var ip string
	var tlsFp string
	var browser string
	var botFp string

	var fpCount int
	var ipCount int
	var ipCountCookie int

	cContext := c.Context()

	if domains.Config.Proxy.Cloudflare {

		ip = utils.SafeString(reqHeaders["Cf-Connecting-Ip"])

		tlsFp = "Cloudflare"
		browser = "Cloudflare"
		botFp = ""
		fpCount = 0

		firewall.Mutex.Lock()
		ipCount = firewall.AccessIps[ip]
		ipCountCookie = firewall.AccessIpsCookie[ip]
		firewall.Mutex.Unlock()
	} else {
		ip = c.IP()

		//Retrieve information about the client
		firewall.Mutex.Lock()
		tlsFp = firewall.Connections[cContext.RemoteAddr().String()]
		fpCount = firewall.UnkFps[tlsFp]
		ipCount = firewall.AccessIps[ip]
		ipCountCookie = firewall.AccessIpsCookie[ip]
		firewall.Mutex.Unlock()

		//Read-Only IMPORTANT: Must be put in mutex if you add the ability to change indexed fingerprints while program is running
		browser = firewall.KnownFingerprints[tlsFp]
		botFp = firewall.BotFingerprints[tlsFp]
	}

	firewall.Mutex.Lock()
	firewall.WindowAccessIps[proxy.Last10SecondTimestamp][ip]++
	domainData = domains.DomainsData[domainName]
	domainData.TotalRequests++
	domains.DomainsData[domainName] = domainData
	firewall.Mutex.Unlock()

	c.Append("baloo-proxy-lite", "1.5")

	//Start the suspicious level where the stage currently is
	susLv := domainData.Stage

	//Ratelimit faster if client repeatedly fails the verification challenge (feel free to play around with the threshhold)
	if ipCountCookie > proxy.FailChallengeRatelimit {
		c.SendString("Blocked by BalooProxy.\nYou have been ratelimited. (R1)")
		return nil
	}

	//Ratelimit spamming Ips (feel free to play around with the threshhold)
	if ipCount > proxy.IPRatelimit {
		c.SendString("Blocked by BalooProxy.\nYou have been ratelimited. (R2)")
		return nil
	}

	//Ratelimit fingerprints that don't belong to major browsers
	if browser == "" {
		if fpCount > proxy.FPRatelimit {
			c.SendString("Blocked by BalooProxy.\nYou have been ratelimited. (R3)")
			return nil
		}

		firewall.Mutex.Lock()
		firewall.WindowUnkFps[proxy.Last10SecondTimestamp][tlsFp]++
		firewall.Mutex.Unlock()
	}

	//Block user-specified fingerprints
	forbiddenFp := firewall.ForbiddenFingerprints[tlsFp]
	if forbiddenFp != "" {
		c.SendString("Blocked by BalooProxy.\nYour browser " + forbiddenFp + " is not allowed.")
		return nil
	}

	//Demonstration of how to use "susLv". Essentially allows you to challenge specific requests with a higher challenge

	//SyncMap because semi-readonly
	settingsQuery, _ := domains.DomainsMap.Load(domainName)
	domainSettings := settingsQuery.(domains.DomainSettings)

	ipInfoCountry := "N/A"
	ipInfoASN := "N/A"
	if domainSettings.IPInfo {
		ipInfoCountry, ipInfoASN = utils.GetIpInfo(ip)
	}

	reqUa := string(cContext.UserAgent())
	cPath := c.Path()
	cOURL := utils.SafeString(c.OriginalURL())
	cookieString := utils.SafeString(reqHeaders["Cookie"])

	if len(domainSettings.CustomRules) != 0 {
		requestVariables := gofilter.Message{
			"ip.src":                net.ParseIP(ip),
			"ip.country":            ipInfoCountry,
			"ip.asn":                ipInfoASN,
			"ip.engine":             browser,
			"ip.bot":                botFp,
			"ip.fingerprint":        tlsFp,
			"ip.http_requests":      ipCount,
			"ip.challenge_requests": ipCountCookie,

			"http.host":       domainName,
			"http.method":     c.Method(),
			"http.url":        c.BaseURL(),
			"http.path":       cPath,
			"http.user_agent": strings.ToLower(reqUa),
			"http.cookie":     cookieString,

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
		case 3:
			encryptedIP = utils.Encrypt(accessKey, proxy.CaptchaOTP)
		default:
			c.SendString("Blocked by BalooProxy.\nSuspicious request of level " + susLvStr)
			return nil
		}
		firewall.CacheIps.Store(accessKey+susLvStr, encryptedIP)
	} else {
		encryptedIP = encryptedCache.(string)
	}

	//Check if client provided correct verification result
	if !strings.Contains(cookieString, "__bProxy_v="+encryptedIP) {

		firewall.Mutex.Lock()
		firewall.WindowAccessIpsCookie[proxy.Last10SecondTimestamp][ip]++
		firewall.Mutex.Unlock()

		//Respond with verification challenge if client didnt provide correct result/none
		switch susLv {
		case 0:
			//This request is not to be challenged (whitelist)
		case 1:
			c.Append("Set-Cookie", "_1__bProxy_v="+encryptedIP+"; SameSite=Lax; path=/; Secure")
			c.Redirect(cOURL, 302)
			return nil
		case 2:
			c.Append("Content-Type", "text/html")
			c.Append("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0") // Prevent special(ed) browsers from caching the challenge
			c.SendString(`<script>let hasMemApi=!1,useMem=!1,hasKnownMem=!1,startMem=null,plugCh=!1,mimeCh=!1;function calcSolution(e){let i=0;for(var t=Math.pow(e,7);t>=0;t--)i+=Math.atan(t)*Math.tan(t);return!0}if(void 0!=performance.memory){if(hasMemApi=!0,startMem=performance.memory,161e5==performance.memory.totalJSHeapSize||127e5==performance.memory.usedJSHeapSize||1e7==performance.memory.usedJSHeapSize||219e4==performance.memory.jsHeapSizeLimit)for(hasKnownMem=!0;calcSolution(performance.memory.usedJSHeapSize);)0>performance.now()&&(hasKnownMem=!1);else calcSolution(8)}if(hasMemApi){let e=performance.memory;if(startMem.usedJSHeapSize==e.usedJSHeapSize&&startMem.jsHeapSizeLimit==e.jsHeapSizeLimit&&startMem.totalJSHeapSize==e.totalJSHeapSize)for(useMem=!0;calcSolution(performance.memory.usedJSHeapSize);)0>performance.now()&&(hasKnownMem=!1)}let pluginString=Object.getOwnPropertyDescriptor(Object.getPrototypeOf(navigator),"plugins").get.toString();"function get plugins() { [native code] }"!=pluginString&&"function plugins() {\n        [native code]\n    }"!=pluginString&&"function plugins() {\n    [native code]\n}"!=pluginString&&(plugCh=!0);let mimeString=Object.getOwnPropertyDescriptor(Object.getPrototypeOf(navigator),"plugins").get.toString();"function get plugins() { [native code] }"!=mimeString&&"function plugins() {\n        [native code]\n    }"!=mimeString&&"function plugins() {\n    [native code]\n}"!=mimeString&&(mimeCh=!0),mimeCh||plugCh||useMem||hasKnownMem||(document.cookie="_2__bProxy_v=` + encryptedIP + `; SameSite=Lax; path=/; Secure",location.href=location.href);</script>`)
			return nil
		case 3:
			secretPart := encryptedIP[:6]
			publicPart := encryptedIP[6:]

			captchaData := ""
			captchaCache, captchaExists := firewall.CacheImgs.Load(secretPart)

			if !captchaExists {
				captchaImg := image.NewRGBA(image.Rect(0, 0, 100, 37))
				utils.AddLabel(captchaImg, rand.Intn(90), rand.Intn(30), publicPart[:6], color.RGBA{255, 0, 0, 100})
				utils.AddLabel(captchaImg, 25, 18, secretPart, color.RGBA{61, 140, 64, 255})

				amplitude := 2.0
				period := float64(37) / 5.0
				displacement := func(x, y int) (int, int) {
					dx := amplitude * math.Sin(float64(y)/period)
					dy := amplitude * math.Sin(float64(x)/period)
					return x + int(dx), y + int(dy)
				}
				captchaImg = utils.WarpImg(captchaImg, displacement)

				var buf bytes.Buffer
				if err := png.Encode(&buf, captchaImg); err != nil {
					c.SendString("BalooProxy Error: Failed to encode captcha: " + err.Error())
					return nil
				}
				data := buf.Bytes()

				captchaData = base64.StdEncoding.EncodeToString(data)

				firewall.CacheImgs.Store(secretPart, captchaData)
			} else {
				captchaData = captchaCache.(string)
			}

			c.Append("Content-Type", "text/html")
			c.Append("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0") // Prevent special(ed) browsers from caching the challenge
			c.SendString(`
			<html>
			<head>
				<style>
				body {
					background-color: #f5f5f5;
					font-family: Arial, sans-serif;
				}

				.center {
					display: flex;
					align-items: center;
					justify-content: center;
					height: 100vh;
				}

				.box {
					background-color: white;
					border: 1px solid #ddd;
					border-radius: 4px;
					padding: 20px;
					width: 500px;
				}

				canvas {
					display: block;
					margin: 0 auto;
					max-width: 100%;
					width: 100%;
					height: auto;
				}

				input[type="text"] {
					width: 100%;
					padding: 12px 20px;
					margin: 8px 0;
					box-sizing: border-box;
					border: 2px solid #ccc;
					border-radius: 4px;
				}

				button {
					width: 100%;
					background-color: #4caf50;
					color: white;
					padding: 14px 20px;
					margin: 8px 0;
					border: none;
					border-radius: 4px;
					cursor: pointer;
				}

				button:hover {
					background-color: #45a049;
				}
				/* Add styles for the animation */ 

.box {
background-color: white;
border: 1px solid #ddd;
border-radius: 4px;
padding: 20px;
width: 500px;
/* Add a transition effect for the height */ 
transition: height 0.1s;
position: block;
}
/* Add a transition effect for the opacity */ 

.box * {
transition: opacity 0.1s;
}
/* Add a success message and style it */ 

.success {
background-color: #dff0d8;
border: 1px solid #d6e9c6;
border-radius: 4px;
color: #3c763d;
padding: 20px;
}

.failure {
background-color: #f0d8d8;
border: 1px solid #e9c6c6;
border-radius: 4px;
color: #763c3c;
padding: 20px;
}
/* Add styles for the collapsible help text */ 

				.collapsible {
					background-color: #f5f5f5;
					color: #444;
					cursor: pointer;
					padding: 18px;
					width: 100%;
					border: none;
					text-align: left;
					outline: none;
					font-size: 15px;
				}

				.collapsible:after {
					content: '\002B';
					color: #777;
					font-weight: bold;
					float: right;
					margin-left: 5px;
				}

				.collapsible.active:after {
					content: "\2212";
				}

				.collapsible:hover {
					background-color: #e5e5e5;
				}

				.collapsible-content {
					padding: 0 18px;
					max-height: 0;
					overflow: hidden;
					transition: max-height 0.2s ease-out;
					background-color: #f5f5f5;
				}
				</style>
			</head>
			<body>
				<div class="center" id="center">
					<div class="box" id="box">
						<h1>Enter the <b>green</b> text you see in the picture</h1>  <canvas id="image" width="100" height="37"></canvas>
						<form onsubmit="return checkAnswer(event)">
							<input id="text" type="text" maxlength="6" placeholder="Solution" required>
							<button type="submit">Submit</button>
						</form>
						<div class="success" id="successMessage" style="display: none;">Success! Redirecting ...</div>
						<div class="failure" id="failMessage" style="display: none;">Failed! Please try again.</div>
						<button class="collapsible">Why am I seeing this page?</button>
						<div class="collapsible-content">
							<p> The website you are trying to visit needs to make sure that you are not a bot. This is a common security measure to protect websites from automated spam and abuse. By entering the characters you see in the picture, you are helping to verify that you are a real person. </p>
						</div>
					</div>
				</div>
			</body>
			<script>
			let canvas=document.getElementById("image");
			let ctx = canvas.getContext("2d");
			var image = new Image();
			image.onload = function() {
				ctx.drawImage(image, (canvas.width-image.width)/2, (canvas.height-image.height)/2);
			};
			image.src = "data:image/png;base64,` + captchaData + `";
			function checkAnswer(event) {
				// Prevent the form from being submitted
				event.preventDefault();
				// Get the user's input
				var input = document.getElementById('text').value;

				document.cookie = '` + ip + `_3__bProxy_v='+input+'` + publicPart + `; SameSite=Lax; path=/; Secure';

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
									location.href=location.href
								}
							}, 20);
						}, 1000)
					} else {
						var failMessage = document.getElementById('failMessage');
						failMessage.style.display = 'block';
						setInterval(function() {
							location.href=location.href
						}, 1000)
					}
				}).catch(function(err){
					var failMessage = document.getElementById('failMessage');
					failMessage.style.display = 'block';
					setInterval(function() {
						location.href=location.href
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
			}
			</script>
			`)
			return nil
		default:
			c.SendString("Blocked by BalooProxy.\nSuspicious request of level " + susLvStr)
			return nil
		}
	}

	//Access logs of clients that passed the challenge
	if browser != "" || botFp != "" {
		access := "[ " + utils.PrimaryColor(proxy.LastSecondTimeFormated) + " ] > \033[35m" + ip + "\033[0m - \033[32m" + browser + botFp + "\033[0m - " + utils.PrimaryColor(reqUa) + " - " + utils.PrimaryColor(cOURL)
		firewall.Mutex.Lock()
		domainData = utils.AddLogs(access, domainName)
		firewall.Mutex.Unlock()
	} else {
		access := "[ " + utils.PrimaryColor(proxy.LastSecondTimeFormated) + " ] > \033[35m" + ip + "\033[0m - \033[31mUNK (" + tlsFp + ")\033[0m - " + utils.PrimaryColor(reqUa) + " - " + utils.PrimaryColor(cOURL)
		firewall.Mutex.Lock()
		domainData = utils.AddLogs(access, domainName)
		firewall.Mutex.Unlock()
	}

	firewall.Mutex.Lock()
	domainData = domains.DomainsData[domainName]
	domainData.BypassedRequests++
	domains.DomainsData[domainName] = domainData
	firewall.Mutex.Unlock()

	//Reserved proxy-paths

	switch cPath {
	case "/_bProxy/stats":
		c.SendString("Stage: " + utils.StageToString(domainData.Stage) + "\nTotal Requests: " + strconv.Itoa(domainData.TotalRequests) + "\nBypassed Requests: " + strconv.Itoa(domainData.BypassedRequests) + "\nTotal R/s: " + strconv.Itoa(domainData.RequestsPerSecond) + "\nBypassed R/s: " + strconv.Itoa(domainData.RequestsBypassedPerSecond) + "\nProxy Fingerprint: " + proxy.Fingerprint)
		return nil
	case "/_bProxy/fingerprint":
		c.SendString("IP: " + ip + "\nASN: " + ipInfoASN + "\nCountry: " + ipInfoCountry + "\nIP Requests: " + strconv.Itoa(ipCount) + "\nIP Challenge Requests: " + strconv.Itoa(ipCountCookie) + "\nSusLV: " + strconv.Itoa(susLv) + "\nFingerprint: " + tlsFp + "\nBrowser: " + browser + botFp)
		return nil
	case "/_bProxy/verified":
		c.SendString("verified")
		return nil
	case "/_bProxy/" + proxy.AdminSecret + "/api/v1":
		result := api.Process(c, domainData)
		if result {
			return nil
		}
	case "/_bProxy/" + proxy.AdminSecret + "/monitor":
		return c.Next()

	//Do not remove or modify this. It is required by the license
	case "/_bProxy/credits":
		c.SendString("BalooProxy Lite; Lightweight http reverse-proxy https://github.com/41Baloo/balooProxy. Protected by GNU GENERAL PUBLIC LICENSE Version 2, June 1991")
		return nil
	}

	_, proxySecretFound := reqHeaders["Proxy-Secret"]
	if proxySecretFound {
		return c.Next() // Return here. This is a v2 api request
	}

	//Allow backend to read client information

	cRequest := c.Request()
	cRequest.Header.Add("X-Real-IP", ip)
	cRequest.Header.Add("Proxy-Real-IP", ip)
	cRequest.Header.Add("Proxy-TLS-FP", tlsFp)
	cRequest.Header.Add("Proxy-TLS-Name", browser+botFp)

	domainSettings.DomainProxy(c)
	return nil
}
