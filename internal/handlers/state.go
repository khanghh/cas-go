package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/common"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
)

type TwoFactorState struct {
	Action      string `json:"action"`
	CallbackURL string `json:"callbackURL"`
	Timestamp   int64  `json:"timestamp"`
}

func getStateEncryptionKey(ctx *fiber.Ctx) string {
	session := sessions.Get(ctx)
	if session.StateEncryptionKey != "" {
		return session.StateEncryptionKey
	}
	keyBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, keyBytes); err != nil {
		return ""
	}
	session.StateEncryptionKey = hex.EncodeToString(keyBytes)
	session.Save()
	return session.StateEncryptionKey
}

func xorBytes(data, key []byte) []byte {
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)]
	}
	return out
}

func encryptState(ctx *fiber.Ctx, state any) string {
	key := getStateEncryptionKey(ctx)
	blob, err := json.Marshal(state)
	if err != nil {
		return ""
	}
	cipherBytes := xorBytes(blob, []byte(key))
	return base64.URLEncoding.EncodeToString([]byte(cipherBytes))
}

func decryptState(ctx *fiber.Ctx, encryted string, state any) error {
	key := getStateEncryptionKey(ctx)
	cipherBytes, err := base64.URLEncoding.DecodeString(encryted)
	if err != nil {
		return err
	}
	blob := xorBytes(cipherBytes, []byte(key))
	return json.Unmarshal(blob, state)
}

func calculateHash(ctx *fiber.Ctx, values ...any) string {
	key := getStateEncryptionKey(ctx)
	return common.CalculateHash(key, values...)
}
