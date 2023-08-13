package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"goProxy/core/domains"
	"goProxy/core/firewall"
	"goProxy/core/pnc"
	"goProxy/core/proxy"
	"goProxy/core/utils"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"github.com/kor44/gofilter"
)

type callbackListener struct {
	net.Listener
}

type callbackConn struct {
	net.Conn
}

func (ln callbackListener) Accept() (net.Conn, error) {
	conn, err := ln.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return callbackConn{Conn: conn}, nil
}

func (c callbackConn) Close() error {
	firewall.Mutex.Lock()
	delete(firewall.Connections, c.RemoteAddr().String())
	firewall.Mutex.Unlock()
	return c.Conn.Close()
}

func Serve() {

	defer pnc.PanicHndl()

	fbConfig := fiber.Config{
		DisableStartupMessage:     true,
		DisableDefaultContentType: true,
		JSONEncoder:               json.Marshal,
		JSONDecoder:               json.Unmarshal,
		IdleTimeout:               proxy.IdleTimeoutDuration,
		ReadTimeout:               proxy.ReadTimeoutDuration,
		WriteTimeout:              proxy.WriteTimeoutDuration,
	}

	if domains.Config.Proxy.Cloudflare {

		httpServer := fiber.New(fbConfig)

		httpServer.Use(func(c *fiber.Ctx) error {
			Middleware(c)

			return nil
		})

		//service.Handler = http.HandlerFunc(Middleware)

		if err := httpServer.Listen(":80"); err != nil {
			panic(err)
		}
	} else {

		// http to https server
		httpServer := fiber.New(fbConfig)
		httpServer.Use(func(c *fiber.Ctx) error {
			return c.Redirect("https://"+c.Hostname()+c.OriginalURL(), fiber.StatusMovedPermanently)
		})

		// Main https server
		httpsServer := fiber.New(fbConfig)

		tlsHandler := &fiber.TLSHandler{}
		serverListener, errListener := tls.Listen("tcp", ":443", &tls.Config{
			GetConfigForClient: firewall.Fingerprint,
			GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				tlsHandler.GetClientInfo(chi)
				return domains.GetCertificate(chi)
			},
		})

		loggingLn := callbackListener{Listener: serverListener}

		if errListener != nil {
			panic(errListener)
		}

		httpsServer.SetTLSHandler(tlsHandler)

		httpsServer.Use(func(c *fiber.Ctx) error {
			Middleware(c)

			return nil
		})

		go func() {
			defer pnc.PanicHndl()
			if err := httpsServer.Listener(loggingLn); err != nil {
				panic(err)
			}
		}()

		if err := httpServer.Listen(":80"); err != nil {
			panic(err)
		}
	}
}

func (rt *RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {

	cacheRes := 0
	reqIP := ""

	if req.Method != "POST" && proxy.CacheEnabled {

		domainSettings := req.Context().Value("domain").(domains.DomainSettings)
		messages := req.Context().Value("filter").(gofilter.Message)

		cacheRes = evalCache(domainSettings, messages)

		if cacheRes != 0 {
			var cacheResponse any
			cacheOk := false
			cacheKey := ""

			switch cacheRes {
			case proxy.CACHE_DEFAULT:
				cacheKey = req.Host + req.URL.Path + req.URL.RawQuery + req.Method
			case proxy.CACHE_DEFAULT_STRICT:
				cacheKey = req.Host + req.URL.Path + req.URL.RawQuery
			case proxy.CACHE_CAREFUL:
				reqIP = strings.Split(req.RemoteAddr, ":")[0]
				cacheKey = req.Host + reqIP + req.URL.Path + req.URL.RawQuery + req.Method
			case proxy.CACHE_CAREFUL_STRICT:
				reqIP = strings.Split(req.RemoteAddr, ":")[0]
				cacheKey = req.Host + reqIP + req.URL.Path + req.URL.RawQuery
			case proxy.CACHE_IGNORE_QUERY:
				cacheKey = req.Host + req.URL.Path
			case proxy.CACHE_QUERY:
				cacheKey = req.Host + req.URL.RawQuery
			case proxy.CACHE_CLIENTIP:
				reqIP = strings.Split(req.RemoteAddr, ":")[0]
				cacheKey = req.Host + reqIP
			default:
			}

			cacheResponse, cacheOk = domains.DomainsCache.Load(cacheKey)

			if cacheOk {
				cachedResp := cacheResponse.(domains.CacheResponse)

				//Check if cache is expired
				if cachedResp.Timestamp > int(proxy.LastSecondTime.Unix()) {

					resp := &http.Response{
						StatusCode: cachedResp.Status,
						Header:     cachedResp.Headers,
						Body:       io.NopCloser(bytes.NewReader(cachedResp.Body)),
					}

					resp.Header.Set("proxy-cache", "HIT")
					return resp, nil
				}

				domains.DomainsCache.Delete(req.Host + req.URL.Path + req.URL.RawQuery)
			}
		}
	}

	//Use Proxy Read Timeout
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
			if !strings.Contains(str, ".") && !strings.Contains(str, "/") && !(strings.Contains(str, "[") && strings.Contains(str, "]")) {
				errMsg += str + " "
			}
		}
		errPage := `
			<!DOCTYPE html>
			<html>
			<head>
			<title>Error: ` + errMsg + `</title>
			<style>
				body {
				font-family: 'Helvetica Neue', sans-serif;
				color: #333;
				margin: 0;
				padding: 0;
				}
				.container {
				display: flex;
				align-items: center;
				justify-content: center;
				height: 100vh;
				background: #fafafa;
				}
				.error-box {
				width: 600px;
				padding: 20px;
				background: #fff;
				border-radius: 5px;
				box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
				}
				.error-box h1 {
				font-size: 36px;
				margin-bottom: 20px;
				}
				.error-box p {
				font-size: 16px;
				line-height: 1.5;
				margin-bottom: 20px;
				}
				.error-box p.description {
				font-style: italic;
				color: #666;
				}
				.error-box a {
				display: inline-block;
				padding: 10px 20px;
				background: #00b8d4;
				color: #fff;
				border-radius: 5px;
				text-decoration: none;
				font-size: 16px;
				}
			</style>
			</head>
			<body>
			<div class="container">
				<div class="error-box">
				<h1>Error: ` + errMsg + `</h1>
				<p>Sorry, there was an error connecting to the backend. That's all we know.</p>
				<a onclick="location.reload()">Reload page</a>
				</div>
			</div>
			</body>
			</html>
		`

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(errPage)),
		}, nil
	}

	//Connection was successfull, got bad response tho
	if resp.StatusCode > 499 && resp.StatusCode < 600 {
		errPage := `
			<!DOCTYPE html>
			<html>
			<head>
			<title>Error: ` + resp.Status + `</title>
			<style>
				body {
				font-family: 'Helvetica Neue', sans-serif;
				color: #333;
				margin: 0;
				padding: 0;
				}
				.container {
				display: flex;
				align-items: center;
				justify-content: center;
				height: 100vh;
				background: #fafafa;
				}
				.error-box {
				width: 600px;
				padding: 20px;
				background: #fff;
				border-radius: 5px;
				box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
				}
				.error-box h1 {
				font-size: 36px;
				margin-bottom: 20px;
				}
				.error-box p {
				font-size: 16px;
				line-height: 1.5;
				margin-bottom: 20px;
				}
				.error-box p.description {
				font-style: italic;
				color: #666;
				}
				.error-box a {
				display: inline-block;
				padding: 10px 20px;
				background: #00b8d4;
				color: #fff;
				border-radius: 5px;
				text-decoration: none;
				font-size: 16px;
				}
			</style>
			</head>
			<body>
			<div class="container">
				<div class="error-box">
				<h1>Error: ` + resp.Status + `</h1>
				<p>Sorry, the backend returned an error. That's all we know.</p>
				<a onclick="location.reload()">Reload page</a>
				</div>
			</div>
			</body>
			</html>
		`

		errBody, errErr := io.ReadAll(resp.Body)
		if errErr == nil && len(errBody) != 0 {
			errPage =
				`
				<!DOCTYPE html>
				<html>
					<head>
						<title>Error: ` + resp.Status + `</title>
						<style>
							body {
							font-family: 'Helvetica Neue', sans-serif;
							color: #333;
							margin: 0;
							padding: 0;
							}
							.container {
							display: flex;
							align-items: center;
							justify-content: center;
							height: 100vh;
							background: #fafafa;
							}
							.error-box {
							width: 600px;
							padding: 20px;
							background: #fff;
							border-radius: 5px;
							box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
							}
							.error-box h1 {
							font-size: 36px;
							margin-bottom: 20px;
							}
							.error-box p {
							font-size: 16px;
							line-height: 1.5;
							margin-bottom: 20px;
							}
							.error-box p.description {
							font-style: italic;
							color: #666;
							}
							.error-box a {
							display: inline-block;
							padding: 10px 20px;
							background: #00b8d4;
							color: #fff;
							border-radius: 5px;
							text-decoration: none;
							font-size: 16px;
							}
						</style>
					</head>
					<body>
						<div class="container">
							<div class="error-box">
							<h1>Error: ` + resp.Status + `</h1>
							<p>Sorry, the backend returned this error.</p>
							<iframe width="100%" height="25%" style="border:1px ridge lightgrey; border-radius: 5px;"
							srcdoc="
								` + string(errBody) + `">
							</iframe>
							<a onclick="location.reload()">Reload page</a>
							</div>
						</div>
					</body>
				</html>
				`
		}
		resp.Body.Close()

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(errPage)),
		}, nil
	}

	resp.Header.Set("proxy-cache", "MISS")

	if cacheRes != 0 && req.Method != "POST" && proxy.CacheEnabled {
		if resp.StatusCode < 300 || (resp.StatusCode < 500 && resp.StatusCode >= 400) {
			bodyBytes, bodyErr := io.ReadAll(resp.Body)

			resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))

			if bodyErr != nil {
				return &http.Response{
					StatusCode: http.StatusBadGateway,
					Body:       io.NopCloser(strings.NewReader("BalooProxy: Failed to read responsebody of backend")),
				}, bodyErr
			}

			var cacheKey string
			switch cacheRes {
			case proxy.CACHE_DEFAULT:
				cacheKey = req.Host + req.URL.Path + req.URL.RawQuery + req.Method
			case proxy.CACHE_DEFAULT_STRICT:
				cacheKey = req.Host + req.URL.Path + req.URL.RawQuery
			case proxy.CACHE_CAREFUL:
				cacheKey = req.Host + reqIP + req.URL.Path + req.URL.RawQuery + req.Method
			case proxy.CACHE_CAREFUL_STRICT:
				cacheKey = req.Host + reqIP + req.URL.Path + req.URL.RawQuery
			case proxy.CACHE_IGNORE_QUERY:
				cacheKey = req.Host + req.URL.Path
			case proxy.CACHE_QUERY:
				cacheKey = req.Host + req.URL.RawQuery
			case proxy.CACHE_CLIENTIP:
				cacheKey = req.Host + reqIP
			default:
				panic("[ " + utils.RedText("Error") + " ]: " + utils.RedText("Cache Error: Failed to get correct cache resp"))
			}

			domains.DomainsCache.Store(cacheKey, domains.CacheResponse{
				Domain:    resp.Request.Host,
				Timestamp: int(proxy.LastSecondTime.Unix()) + 3600, //Cache for an hour
				Status:    resp.StatusCode,
				Headers:   resp.Header,
				Body:      bodyBytes,
			})
		}
	}
	return resp, nil
}

func evalCache(domainSettings domains.DomainSettings, message gofilter.Message) int {
	for _, rule := range domainSettings.CacheRules {
		if rule.Filter.Apply(message) {
			switch rule.Action {
			case "BYPASS":
				return 0
			case "DEFAULT":
				return proxy.CACHE_DEFAULT
			case "DEFAULT_STRICT":
				return proxy.CACHE_DEFAULT_STRICT
			case "CAREFUL":
				return proxy.CACHE_CAREFUL
			case "CAREFUL_STRICT":
				return proxy.CACHE_CAREFUL_STRICT
			case "IGNORE_QUERY":
				return proxy.CACHE_IGNORE_QUERY
			case "QUERY":
				return proxy.CACHE_QUERY
			case "CLIENTIP":
				return proxy.CACHE_CLIENTIP
			default:
			}
		}
	}
	return 0
}

type RoundTripper struct {
}
