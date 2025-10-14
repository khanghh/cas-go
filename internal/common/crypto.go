package common

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func CalculateHash(key string, inputs ...interface{}) string {
	if len(inputs) == 0 {
		return ""
	}
	h := hmac.New(sha256.New, []byte(key))
	for _, val := range inputs {
		switch v := val.(type) {
		case []byte:
			h.Write(v)
		default:
			h.Write([]byte(fmt.Sprintf("%v", v)))
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}
