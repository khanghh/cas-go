package twofactor

import (
	"crypto/rand"
	"encoding/base32"
)

func randomSecretKey(length int) string {
	data := make([]byte, length)
	_, err := rand.Read(data)
	if err != nil {
		panic(err)
	}
	// base32NoPadding := base32.StdEncoding.WithPadding(base32.NoPadding)
	return base32.StdEncoding.EncodeToString(data)[:length]
}
