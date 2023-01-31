package utils

import (
	"crypto/md5"
	"encoding/hex"
	"math/rand"
	"time"
)

func Encrypt(input string, key string) string {
	hasher := md5.New()
	hasher.Write([]byte(input + key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func RandomString(length int) string {
	rand.Seed(time.Now().UnixNano())
	var rnd = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	res := make([]rune, length)
	for i := range res {
		res[i] = rnd[rand.Intn(len(rnd))]
	}
	return string(res)
}
