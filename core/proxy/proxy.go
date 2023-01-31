package proxy

var (
	WatchedDomain string
	TWidth        int
	THeight       int
	Cloudflare    bool
	MaxLogLength  int

	CookieSecret  string
	JSSecret      string
	CaptchaSecret string

	IPRatelimit            int
	FPRatelimit            int
	FailChallengeRatelimit int
	FailRequestRatelimit   int

	MaxHeaderSize int
	MaxBodySize   int

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
