package proxy

import "time"

const (
	ProxyVersion float64 = 1.5
)

var (
	Fingerprint string

	WatchedDomain string
	TWidth        int
	THeight       int
	Cloudflare    bool
	MaxLogLength  int

	CpuUsage string
	RamUsage string

	AdminSecret string
	APISecret   string

	CookieSecret string
	CookieOTP    string

	JSSecret string
	JSOTP    string

	CaptchaSecret string
	CaptchaOTP    string

	IdleTimeout       = 5
	ReadTimeout       = 5
	WriteTimeout      = 7
	ReadHeaderTimeout = 5

	IdleTimeoutDuration       = time.Duration(IdleTimeout).Abs() * time.Second
	ReadTimeoutDuration       = time.Duration(ReadTimeout).Abs() * time.Second
	WriteTimeoutDuration      = time.Duration(WriteTimeout).Abs() * time.Second
	ReadHeaderTimeoutDuration = time.Duration(ReadHeaderTimeout).Abs() * time.Second

	RatelimitWindow = 120

	IPRatelimit            int
	FPRatelimit            int
	FailChallengeRatelimit int
	FailRequestRatelimit   int

	RealTimeLogs = false

	CurrHour               int
	CurrHourStr            string
	LastSecondTime         time.Time
	LastSecondTimeFormated string
	LastSecondTimestamp    int
	Last10SecondTimestamp  int

	Initialised = false
)
