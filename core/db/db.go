package db

import (
	"time"

	"github.com/boltdb/bolt"
)

var (
	Instance *Container = new(Container)
)

type Container struct {
	DB     *bolt.DB
	Uptime time.Time
}
