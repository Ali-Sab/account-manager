package handler

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
)

func cryptoRandRead(b []byte) (int, error) {
	return rand.Read(b)
}

func encodeHex(b []byte) string {
	return hex.EncodeToString(b)
}

func encodeBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
