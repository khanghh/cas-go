package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
	"github.com/khanghh/cas-go/model"
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

type BaseAuthHandler struct {
	stateEncryptionKey string
}

func NewBaseAuthHandler(stateEncryptionKey string) *BaseAuthHandler {
	return &BaseAuthHandler{
		stateEncryptionKey: stateEncryptionKey,
	}
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
func (h *BaseAuthHandler) encryptState(state AuthState) string {
	var buffer bytes.Buffer
	gob.NewEncoder(&buffer).Encode(state)
	encryptedState := xorEncrypt(buffer.Bytes(), h.stateEncryptionKey)
	return base64.URLEncoding.EncodeToString(encryptedState)
}

// decryptState decrypts the state previously encrypted passed to the oauth provider
func (s *BaseAuthHandler) decryptState(encryptedState string) (AuthState, error) {
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

func (h *BaseAuthHandler) redirect(ctx *fiber.Ctx, location string, params fiber.Map) error {
	url, err := url.Parse(location)
	if err != nil {
		return err
	}
	query := url.Query()
	for key, value := range params {
		if value != nil && value != "" {
			query.Set(key, fmt.Sprintf("%v", value))
		}
	}
	url.RawQuery = query.Encode()
	return ctx.Redirect(url.String())
}

func (h *BaseAuthHandler) redirectLogin(ctx *fiber.Ctx, serviceURL string, logout bool) error {
	queries := fiber.Map{"service": serviceURL}
	if logout {
		sessions.Destroy(ctx)
	}
	return h.redirect(ctx, "/login", queries)
}

func (h *BaseAuthHandler) redirectInternal(ctx *fiber.Ctx, location string) error {
	ctx.Path(location)
	ctx.Method(http.MethodGet)
	return ctx.RestartRouting()
}

func (h *BaseAuthHandler) handleLoginSuccess(ctx *fiber.Ctx, user *model.User, userOAuth *model.UserOAuth) error {
	sessions.Destroy(ctx)
	var oauthID uint
	if userOAuth != nil {
		oauthID = userOAuth.ID
	}
	sessions.Set(ctx, sessions.SessionData{
		IP:        ctx.IP(),
		UserID:    user.ID,
		OAuthID:   oauthID,
		LoginTime: time.Now(),
	})
	return nil
}
