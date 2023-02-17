package utils

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"time"
)

func Encrypt(input string, key string) string {
	hasher := md5.New()
	hasher.Write([]byte(input + key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func EncryptSha(input string, key string) string {
	hasher := sha256.New()
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

func HashToInt(hash string) int {
	subset := (uint16(hash[0]) << 8) | uint16(hash[1])
	return int(subset)%15 + 1
}
