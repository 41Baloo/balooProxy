package proxy

var (
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
	ReadTimout        = 5
	WriteTimeout      = 7
	ReadHeaderTimeout = 5

	IPRatelimit            int
	FPRatelimit            int
	FailChallengeRatelimit int
	FailRequestRatelimit   int

	MaxHeaderSize int
	MaxBodySize   int

	RealTimeLogs = false

	//Path + Query + Method
	CACHE_DEFAULT = 1
	//Path + Query
	CACHE_DEFAULT_STRICT = 2
	//IP + Path + Query + Method
	CACHE_CAREFUL = 3
	//IP + Path + Query
	CACHE_CAREFUL_STRICT = 4
	//Path
	CACHE_IGNORE_QUERY = 5
	//Query
	CACHE_QUERY = 6
	//IP
	CACHE_CLIENTIP = 7
)
