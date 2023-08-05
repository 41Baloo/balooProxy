package domains

import (
	"crypto/tls"
	"fmt"
	"goProxy/core/pnc"
	"net/http"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/kor44/gofilter"
)

var (
	Domains      = []string{}
	DomainsMap   sync.Map
	DomainsDataN = map[string]DomainData{}
	DomainsData  = &DomainsDataDebug{
		m: DomainsDataN,
	}
	DomainsCache sync.Map
	Config       *Configuration
)

type DomainsDataDebug struct {
	m map[string]DomainData
}

func (sm DomainsDataDebug) GetMap() map[string]DomainData {
	pnc.LogError("[!] Map Requested")
	return sm.m
}

func (sm DomainsDataDebug) Set(key string, value DomainData) {

	if _, exists := sm.m[key]; exists {
		pnc.LogError("Overwriting key: " + key)
	} else {
		pnc.LogError("[!] Setting key: " + key)
	}

	sm.m[key] = value
}

func (sm DomainsDataDebug) Get(key string) DomainData {

	pnc.LogError("Getting key: " + key)
	val := sm.m[key]
	return val
}

func (sm DomainsDataDebug) Delete(key string) {

	fmt.Printf("Deleting key: %s\n", key)
	delete(sm.m, key)
}

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
	CacheRules          []JsonRule      `json:"cacheRules"`
	BypassStage1        int             `json:"bypassStage1"`
	BypassStage2        int             `json:"bypassStage2"`
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

	CacheRules    []Rule
	RawCacheRules []JsonRule

	DomainProxy        func(*fiber.Ctx) error
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
	Stage            int
	StageManuallySet bool
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
	Cloudflare  bool              `json:"cloudflare"`
	AdminSecret string            `json:"adminsecret"`
	APISecret   string            `json:"apisecret"`
	Secrets     map[string]string `json:"secrets"`
	Timeout     TimeoutSettings   `json:"timeout"`
	Ratelimits  map[string]int    `json:"ratelimits"`
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
