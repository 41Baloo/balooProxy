package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"goProxy/core/api"
	"goProxy/core/domains"
	"goProxy/core/firewall"
	"goProxy/core/proxy"
	"goProxy/core/utils"
	"image"
	"image/color"
	"image/png"
	"math"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/kor44/gofilter"
)

func Middleware(writer http.ResponseWriter, request *http.Request) {
	domainName := request.Host

	firewall.Mutex.Lock()
	domainData := domains.DomainsData[domainName]
	firewall.Mutex.Unlock()

	if domainData.Stage == 0 {
		writer.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(writer, "balooProxy: "+domainName+" does not exist. If you are the owner please check your config.json if you believe this is a mistake")
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

		firewall.Mutex.Lock()
		ipCount = firewall.AccessIps[ip]
		ipCountCookie = firewall.AccessIpsCookie[ip]
		firewall.Mutex.Unlock()
	} else {
		ip = strings.Split(request.RemoteAddr, ":")[0]

		//Retrieve information about the client
		firewall.Mutex.Lock()
		tlsFp = firewall.Connections[request.RemoteAddr]

		fpCount = firewall.UnkFps[tlsFp]
		ipCount = firewall.AccessIps[ip]
		ipCountCookie = firewall.AccessIpsCookie[ip]
		firewall.Mutex.Unlock()

		//Read-Only IMPORTANT: Must be put in mutex if you add the ability to change indexed fingerprints while program is running
		browser = firewall.KnownFingerprints[tlsFp]
		botFp = firewall.BotFingerprints[tlsFp]
	}

	firewall.Mutex.Lock()
	domainData = domains.DomainsData[domainName]
	domainData.TotalRequests++
	domains.DomainsData[domainName] = domainData
	firewall.Mutex.Unlock()

	writer.Header().Set("baloo-Proxy", "1.2")

	//Start the suspicious level where the stage currently is
	susLv := domainData.Stage

	//Ratelimit faster if client repeatedly fails the verification challenge (feel free to play around with the threshhold)
	if ipCountCookie > proxy.FailChallengeRatelimit {
		writer.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(writer, "Blocked by BalooProxy.\nYou have been ratelimited. (R1)")
		return
	}

	//Ratelimit spamming Ips (feel free to play around with the threshhold)
	if ipCount > proxy.IPRatelimit {
		writer.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(writer, "Blocked by BalooProxy.\nYou have been ratelimited. (R2)")
		return
	}

	//Ratelimit fingerprints that don't belong to major browsers
	if browser == "" {
		if fpCount > proxy.FPRatelimit {
			writer.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(writer, "Blocked by BalooProxy.\nYou have been ratelimited. (R3)")
			return
		}

		firewall.Mutex.Lock()
		firewall.UnkFps[tlsFp] = firewall.UnkFps[tlsFp] + 1
		firewall.Mutex.Unlock()
	}

	//Block user-specified fingerprints
	forbiddenFp := firewall.ForbiddenFingerprints[tlsFp]
	if forbiddenFp != "" {
		writer.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(writer, "Blocked by BalooProxy.\nYour browser %s is not allowed.", forbiddenFp)
		return
	}

	//Demonstration of how to use "susLv". Essentially allows you to challenge specific requests with a higher challenge

	settingsQuery, _ := domains.DomainsMap.Load(domainName)
	domainSettings := settingsQuery.(domains.DomainSettings)

	ipInfoCountry := "N/A"
	ipInfoASN := "N/A"
	if domainSettings.IPInfo {
		ipInfoCountry, ipInfoASN = utils.GetIpInfo(ip)
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

		"http.host":      request.Host,
		"http.version":   request.Proto,
		"http.method":    request.Method,
		"http.url":       request.RequestURI,
		"http.query":     request.URL.RawQuery,
		"http.path":      request.URL.Path,
		"http.UserAgent": strings.ToLower(request.UserAgent()),
		"http.cookie":    request.Header.Get("Cookie"),
		"http.headers":   fmt.Sprint(request.Header),

		"proxy.stage":         domainData.Stage,
		"proxy.cloudflare":    domains.Config.Proxy.Cloudflare,
		"proxy.stage_locked":  domainData.StageManuallySet,
		"proxy.attack":        domainData.RawAttack,
		"proxy.bypass_attack": domainData.BypassAttack,
		"proxy.rps":           domainData.RequestsPerSecond,
		"proxy.rpsAllowed":    domainData.RequestsBypassedPerSecond,
	}

	susLv = firewall.EvalFirewallRule(domainSettings, requestVariables, susLv)

	//Check if encryption-result is already "cached" to prevent load on reverse proxy
	firewall.Mutex.Lock()
	encryptedIP := firewall.CacheIps[ip+fmt.Sprint(susLv)]
	firewall.Mutex.Unlock()

	if encryptedIP == "" {
		hr, _, _ := time.Now().Clock()
		switch susLv {
		case 0:
			//whitelisted
		case 1:
			encryptedIP = utils.Encrypt(ip+tlsFp+fmt.Sprint(hr), proxy.CookieOTP)
		case 2:
			encryptedIP = utils.Encrypt(ip+tlsFp+fmt.Sprint(hr), proxy.JSOTP)
		case 3:
			encryptedIP = utils.Encrypt(ip+tlsFp+fmt.Sprint(hr), proxy.CaptchaOTP)
		default:
			writer.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(writer, "Blocked by BalooProxy.\nSuspicious request of level %d (base %d)", susLv, domainData.Stage)
			return
		}
		firewall.Mutex.Lock()
		firewall.CacheIps[ip+fmt.Sprint(susLv)] = encryptedIP
		firewall.Mutex.Unlock()
	}

	//Check if client provided correct verification result
	if !strings.Contains(request.Header.Get("Cookie"), fmt.Sprintf("__bProxy_v=%s", encryptedIP)) {

		firewall.Mutex.Lock()
		firewall.AccessIpsCookie[ip] = firewall.AccessIpsCookie[ip] + 1
		firewall.Mutex.Unlock()

		//Respond with verification challenge if client didnt provide correct result/none
		switch susLv {
		case 0:
			//This request is not to be challenged (whitelist)
		case 1:
			writer.Header().Set("Set-Cookie", "_1__bProxy_v="+encryptedIP+"; SameSite=None; path=/; Secure")
			http.Redirect(writer, request, request.URL.RequestURI(), http.StatusTemporaryRedirect)
			return
		case 2:
			writer.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(writer, `<script>document.cookie = '_2__bProxy_v=%s; SameSite=None; path=/; Secure';window.location.reload();</script>`, encryptedIP)
			return
		case 3:
			secretPart := encryptedIP[:6]
			publicPart := encryptedIP[6:]

			firewall.Mutex.Lock()
			captchaData := firewall.CacheImgs[secretPart]
			firewall.Mutex.Unlock()

			if captchaData == "" {
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
					fmt.Fprintf(writer, `BalooProxy Error: Failed to encode captcha: %s`, err)
					return
				}
				data := buf.Bytes()

				captchaData = base64.StdEncoding.EncodeToString(data)

				firewall.Mutex.Lock()
				firewall.CacheImgs[secretPart] = captchaData
				firewall.Mutex.Unlock()
			}

			writer.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(writer,
				`
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
							max-width: 100%%;
							width: 100%%;
    						height: auto;
						}

						input[type="text"] {
							width: 100%%;
							padding: 12px 20px;
							margin: 8px 0;
							box-sizing: border-box;
							border: 2px solid #ccc;
							border-radius: 4px;
						}

						button {
							width: 100%%;
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
							width: 100%%;
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
					}
					</script>
					`, captchaData, ip, publicPart)
			return
		default:
			writer.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(writer, "Blocked by BalooProxy.\nSuspicious request of level %d (base %d)", susLv, domainData.Stage)
			return
		}
	}

	//Access logs of clients that passed the challenge
	if browser != "" || botFp != "" {
		access := "[ " + utils.RedText(time.Now().Format("15:04:05")) + " ] > \033[35m" + ip + "\033[0m - \033[32m" + browser + botFp + "\033[0m - " + utils.RedText(request.UserAgent()) + " - " + utils.RedText(request.RequestURI)
		firewall.Mutex.Lock()
		domainData = utils.AddLogs(access, domainName)
		firewall.AccessIps[ip] = firewall.AccessIps[ip] + 1
		firewall.Mutex.Unlock()
	} else {
		access := "[ " + utils.RedText(time.Now().Format("15:04:05")) + " ] > \033[35m" + ip + "\033[0m - \033[31mUNK (" + tlsFp + ")\033[0m - " + utils.RedText(request.UserAgent()) + " - " + utils.RedText(request.RequestURI)
		firewall.Mutex.Lock()
		domainData = utils.AddLogs(access, domainName)
		firewall.AccessIps[ip] = firewall.AccessIps[ip] + 1
		firewall.Mutex.Unlock()
	}

	ctx := context.WithValue(request.Context(), "filter", requestVariables)
	request = request.WithContext(ctx)
	ctx = context.WithValue(request.Context(), "domain", domainSettings)
	request = request.WithContext(ctx)

	firewall.Mutex.Lock()
	domainData = domains.DomainsData[domainName]
	domainData.BypassedRequests++
	domains.DomainsData[domainName] = domainData
	firewall.Mutex.Unlock()

	//Reserved proxy-paths
	switch request.URL.Path {
	case "/_bProxy/stats":
		writer.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(writer, "Stage: %s\nTotal Requests: %s\nBypassed Requests: %s\nTotal R/s: %s\nBypassed R/s: %s", fmt.Sprint(domainData.Stage), fmt.Sprint(domainData.TotalRequests), fmt.Sprint(domainData.BypassedRequests), fmt.Sprint(domainData.RequestsPerSecond), fmt.Sprint(domainData.RequestsBypassedPerSecond))
		return
	case "/_bProxy/fingerprint":
		writer.Header().Set("Content-Type", "text/plain")

		firewall.Mutex.Lock()
		fmt.Fprintf(writer, "IP: "+ip+"\nASN: "+fmt.Sprint(ipInfoASN)+"\nCountry: "+ipInfoCountry+"\nIP Requests: "+fmt.Sprint(ipCount)+"\nIP Challenge Requests: "+fmt.Sprint(firewall.AccessIpsCookie[ip])+"\nSusLV: "+fmt.Sprint(susLv)+"\nFingerprint: "+tlsFp+"\nBrowser: "+browser+botFp)
		firewall.Mutex.Unlock()
		return
	case "/_bProxy/verified":
		writer.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(writer, "verified")
		return
	case "/_bProxy/" + proxy.AdminSecret + "/api/v1":
		result := api.Process(writer, request, domainData)
		if result {
			return
		}
	//Do not remove or modify this. It is required by the license
	case "/_bProxy/credits":
		writer.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(writer, "BalooProxy; Lightweight http reverse-proxy https://github.com/41Baloo/balooProxy. Protected by GNU GENERAL PUBLIC LICENSE Version 2, June 1991")
		return
	}

	//Allow backend to read client information
	request.Header.Add("x-real-ip", ip)
	request.Header.Add("proxy-real-ip", ip)
	request.Header.Add("proxy-tls-fp", tlsFp)
	request.Header.Add("proxy-tls-name", browser+botFp)

	domainSettings.DomainProxy.ServeHTTP(writer, request)
}
