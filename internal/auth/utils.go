package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
)

func signHMAC(secret, message string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	signature := mac.Sum(nil)
	return base64.StdEncoding.EncodeToString(signature)
}

func verifyHMAC(secret, message, signatureB64 string) bool {
	expected := signHMAC(secret, message)
	return hmac.Equal([]byte(expected), []byte(signatureB64))
}

// removeQueryFromURL parses the service URL and returns the base URL without query
func removeQueryFromURL(urlWithQuery string) string {
	parsed, err := url.Parse(urlWithQuery)
	if err != nil {
		return ""
	}
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	return parsed.String()
}
