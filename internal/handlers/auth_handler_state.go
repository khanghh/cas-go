package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"strings"
	"time"
)

const (
	actionPasswordLogin = "password_login"
	actionOAuthLogin    = "oauth_login"
	actionOAuthLink     = "oauth_link"
)

type AuthState struct {
	ServiceURL string
	Action     string
	CreateTime time.Time
}

func xorEncrypt(data []byte, key string) []byte {
	keyLen := len(key)
	encrypted := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		encrypted[i] = data[i] ^ key[i%keyLen]
	}
	return encrypted
}

// encryptState encrypts the state before passing to the oauth provider
func (s *AuthHandler) encryptState(state AuthState) string {
	var buffer bytes.Buffer
	gob.NewEncoder(&buffer).Encode(state)
	encryptedState := xorEncrypt(buffer.Bytes(), s.stateEncryptionKey)
	return base64.URLEncoding.EncodeToString(encryptedState)
}

// decryptState decrypts the state previously encrypted passed to the oauth provider
func (s *AuthHandler) decryptState(encryptedState string) (AuthState, error) {
	encryptedBytes, err := base64.URLEncoding.DecodeString(encryptedState)
	if err != nil {
		return AuthState{}, err
	}
	decryptedBytes := xorEncrypt(encryptedBytes, s.stateEncryptionKey)
	reader := strings.NewReader(string(decryptedBytes))
	var state AuthState
	err = gob.NewDecoder(reader).Decode(&state)
	if err != nil {
		return AuthState{}, err
	}
	return state, err
}
