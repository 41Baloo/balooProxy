package domains

import (
	"crypto/tls"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"github.com/kor44/gofilter"
)

var (
	Domains     = []string{}
	DomainsMap  sync.Map
	DomainsData = map[string]DomainData{}
	Config      *Configuration
)

type Configuration struct {
	Proxy   Proxy    `json:"proxy"`
	Domains []Domain `json:"domains"`
}

type Domain struct {
	Name                string          `json:"name"`
	Backend             string          `json:"backend"`
	Scheme              string          `json:"scheme"`
	Certificate         string          `json:"certificate"`
	Key                 string          `json:"key"`
	Webhook             WebhookSettings `json:"webhook"`
	FirewallRules       []JsonRule      `json:"firewallRules"`
	BypassStage1        int             `json:"bypassStage1"`
	BypassStage2        int             `json:"bypassStage2"`
	Stage2Difficulty    int             `json:"stage2Difficulty"`
	DisableBypassStage3 int             `json:"disableBypassStage3"`
	DisableRawStage3    int             `json:"disableRawStage3"`
	DisableBypassStage2 int             `json:"disableBypassStage2"`
	DisableRawStage2    int             `json:"disableRawStage2"`
}

type DomainSettings struct {
	Name string

	CustomRules    []Rule
	IPInfo         bool
	RawCustomRules []JsonRule

	DomainProxy        *httputil.ReverseProxy
	DomainCertificates tls.Certificate
	DomainWebhooks     WebhookSettings

	BypassStage1        int
	BypassStage2        int
	DisableBypassStage3 int
	DisableRawStage3    int
	DisableBypassStage2 int
	DisableRawStage2    int
}

type DomainData struct {
	Name             string
	Stage            int
	StageManuallySet bool
	Stage2Difficulty int
	RawAttack        bool
	BypassAttack     bool
	BufferCooldown   int

	LastLogs []string

	TotalRequests    int
	BypassedRequests int

	PrevRequests int
	PrevBypassed int

	RequestsPerSecond             int
	RequestsBypassedPerSecond     int
	PeakRequestsPerSecond         int
	PeakRequestsBypassedPerSecond int
	RequestLogger                 []RequestLog
}

type Proxy struct {
	Cloudflare      bool              `json:"cloudflare"`
	AdminSecret     string            `json:"adminsecret"`
	APISecret       string            `json:"apisecret"`
	Secrets         map[string]string `json:"secrets"`
	Timeout         TimeoutSettings   `json:"timeout"`
	RatelimitWindow int               `json:"ratelimit_time"`
	Ratelimits      map[string]int    `json:"ratelimits"`
	Colors          []string          `json:"colors"`
}

type TimeoutSettings struct {
	Idle       int `json:"idle"`
	Read       int `json:"read"`
	Write      int `json:"write"`
	ReadHeader int `json:"read_header"`
}

type WebhookSettings struct {
	URL            string `json:"url"`
	Name           string `json:"name"`
	Avatar         string `json:"avatar"`
	AttackStartMsg string `json:"attack_start_msg"`
	AttackStopMsg  string `json:"attack_stop_msg"`
}

type JsonRule struct {
	Expression string `json:"expression"`
	Action     string `json:"action"`
}

type Rule struct {
	Filter *gofilter.Filter
	Action string
}

type RequestLog struct {
	Time     time.Time
	Allowed  int
	Total    int
	CpuUsage string
}

type CacheResponse struct {
	Domain    string
	Timestamp int
	Status    int
	Headers   http.Header
	Body      []byte
}
