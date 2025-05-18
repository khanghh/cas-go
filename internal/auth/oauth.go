package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/gob"
	"strings"

	"golang.org/x/oauth2"
)

const (
	OAuthProviderGoogle  = "google"
	OAuthProviderDiscord = "discord"
	stateEncryptionKey   = "secretKey"
	OAuthActionLogin     = "login"
	OAuthActionLink      = "link"
)

type OAuthState struct {
	Service string
	Action  string
}

type OAuthToken = oauth2.Token

type OAuthUserInfo struct {
	ID      string
	Email   string
	Name    string
	Picture string
}
type OAuthProvider interface {
	Name() string
	GetOAuthUrl(callbackUrl string, state string) string
	ExchangeToken(ctx context.Context, code string) (*OAuthToken, error)
	GetUserInfo(ctx context.Context, token *OAuthToken) (*OAuthUserInfo, error)
}

// XOR encryption/decryption function (same operation for both)
func xorEncrypt(data []byte, key string) []byte {
	keyLen := len(key)
	encrypted := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		encrypted[i] = data[i] ^ key[i%keyLen]
	}
	return encrypted
}

// EncryptState encrypts the state before passing to the oauth provider
func EncryptOAuthState(state OAuthState) string {
	var buffer bytes.Buffer
	gob.NewEncoder(&buffer).Encode(state)
	encryptedState := xorEncrypt(buffer.Bytes(), stateEncryptionKey)
	return base64.URLEncoding.EncodeToString(encryptedState)
}

// DecryptOAuthState decrypts the state previously encrypted passed to the oauth provider
func DecryptOAuthState(encryptedState string) (*OAuthState, error) {
	encryptedBytes, err := base64.URLEncoding.DecodeString(encryptedState)
	if err != nil {
		return nil, err
	}
	decryptedBytes := xorEncrypt(encryptedBytes, stateEncryptionKey)
	reader := strings.NewReader(string(decryptedBytes))
	var state OAuthState
	err = gob.NewDecoder(reader).Decode(&state)
	if err != nil {
		return nil, err
	}
	return &state, err
}
