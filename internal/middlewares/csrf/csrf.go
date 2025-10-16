package csrf

import (
	"crypto/rand"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"path"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/middlewares/sessions"
	"github.com/khanghh/cas-go/params"
)

const (
	CSRFTokenSessionKey = "_csrf"
)

var (
	ErrInvalidToken = errors.New("invalid CSRF token")
)

type CSRF struct {
	Token     string
	ExpiresAt time.Time
}

func init() {
	gob.Register(CSRF{})
}

func Get(session *sessions.Session) CSRF {
	csrf, ok := session.Get(CSRFTokenSessionKey).(CSRF)
	if !ok {
		csrf = generateCSRF()
		session.Set(CSRFTokenSessionKey, csrf)
	}
	return csrf
}

func Verify(ctx *fiber.Ctx) bool {
	token := ctx.Get("X-CSRF-Token")
	if token == "" && ctx.Method() == fiber.MethodPost {
		token = ctx.FormValue("_csrf")
	}

	csrf := Get(sessions.Get(ctx))
	if time.Now().After(csrf.ExpiresAt) || csrf.Token != token {
		return false
	}
	return true
}

func randomToken() string {
	const tokenLength = 32
	b := make([]byte, tokenLength)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate CSRF token: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func generateCSRF() CSRF {
	return CSRF{
		Token:     randomToken(),
		ExpiresAt: time.Now().Add(params.CSRFTokenExpiration),
	}
}

type Config struct {
	ExcludePaths []string
}

func New(config Config) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		for _, p := range config.ExcludePaths {
			if ok, _ := path.Match(p, ctx.Path()); ok {
				return ctx.Next()
			}
		}
		session := sessions.Get(ctx)
		data, ok := session.Get(CSRFTokenSessionKey).(CSRF)
		if !ok || time.Now().After(data.ExpiresAt) {
			session.Set(CSRFTokenSessionKey, generateCSRF())
		}
		return ctx.Next()
	}
}
