package dashboard

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/boltdb/bolt"
)

var (
	Instance      *Container = new(Container)
	AdminUser                = ""
	AdminPassword            = ""
)

func init() {
	var err error
	Instance.DB, err = bolt.Open("proxyData.db", 0600, nil)
	if err != nil {
		panic(err)
	}
	//defer boltDb.Close()

	Instance.DB.Update(func(tx *bolt.Tx) error {
		var boltErr error
		_, boltErr = tx.CreateBucketIfNotExists([]byte("user"))
		if boltErr != nil {
			panic("[ ! ] [ Failed To Create Bucket ] > " + boltErr.Error())
		}

		return nil
	})
	InitAuth()
}

func InitAuth() {
	Instance.DB.View(func(tx *bolt.Tx) error {
		users := tx.Bucket([]byte("user"))

		users.ForEach(func(key, value []byte) error {
			AdminUser = string(key)
			AdminPassword = string(value)
			return nil
		})

		return nil
	})
}

func RegisterAdmin(username string, password string) error {
	return Instance.DB.Update(func(tx *bolt.Tx) error {
		user := tx.Bucket([]byte("user"))

		err := user.Put([]byte(username), []byte(fmt.Sprint(sha256.Sum256([]byte(password)))))
		if err != nil {
			return err
		}
		return nil
	})
}

func IsAuthed(request *http.Request) bool {
	return strings.Contains(request.Header.Get("Cookie"), fmt.Sprintf("auth_bProxy_v=%x", sha256.Sum256([]byte(AdminPassword))))
}

type Container struct {
	DB     *bolt.DB
	Uptime time.Time
}
