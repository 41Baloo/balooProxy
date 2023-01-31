package firewall

import "time"

type RequestLog struct {
	Time    time.Time
	Allowed int
	Total   int
}
