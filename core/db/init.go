package db

import (
	"fmt"

	"github.com/boltdb/bolt"
)

func Connect() {
	var err error
	Instance.DB, err = bolt.Open("proxyCache.db", 0600, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	//defer boltDb.Close()

	Instance.DB.Update(func(tx *bolt.Tx) error {
		var boltErr error
		_, boltErr = tx.CreateBucketIfNotExists([]byte("countries"))
		if boltErr != nil {
			panic("[ ! ] [ Failed To Create Bucket ] > " + boltErr.Error())
		}

		_, boltErr = tx.CreateBucketIfNotExists([]byte("asns"))
		if boltErr != nil {
			panic("[ ! ] [ Failed To Create Bucket ] > " + boltErr.Error())
		}
		return nil
	})
}
