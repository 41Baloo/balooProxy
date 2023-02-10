package firewall

import "github.com/kor44/gofilter"

func init() {
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
	gofilter.RegisterField("http.url", gofilter.FT_STRING)
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
}
