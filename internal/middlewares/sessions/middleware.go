package sessions

import (
	"crypto/rand"
	"encoding/gob"
	"encoding/hex"
	"log/slog"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
)

const (
	injectSessionKey = "session"
	sessionDataKey   = "data"
)

type Middleware func(next fiber.Handler) fiber.Handler

type SessionData struct {
	id         string    // session id
	IP         string    // client ip address
	UserID     uint      // user id
	OAuthID    uint      // user oauth id
	LoginTime  time.Time // last login time
	LastSeen   time.Time // last request time
	ExpireTime time.Time // session expire time
}

func (s SessionData) ID() string {
	return s.id
}

func init() {
	gob.Register(SessionData{})
}

func GenerateSessionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		slog.Error("Could not generate session id", "error", err)
		return ""
	}
	return hex.EncodeToString(b)
}

func Get(ctx *fiber.Ctx) SessionData {
	session := ctx.Locals(injectSessionKey).(*session.Session)
	data, _ := session.Get(sessionDataKey).(SessionData)
	data.id = session.ID()
	return data
}

func Set(ctx *fiber.Ctx, data SessionData) {
	session := ctx.Locals(injectSessionKey).(*session.Session)
	session.Set(sessionDataKey, data)
}

func Destroy(ctx *fiber.Ctx) error {
	sess := ctx.Locals(injectSessionKey).(*session.Session)
	return sess.Destroy()
}

func injectSession(store *session.Store, next fiber.Handler) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		session, err := store.Get(ctx)
		if err != nil {
			return err
		}

		ctx.Locals(injectSessionKey, session)
		if err := next(ctx); err != nil {
			return err
		}

		data, ok := session.Get(sessionDataKey).(SessionData)
		if ok {
			data.LastSeen = time.Now()
			session.Set(sessionDataKey, data)
			return session.Save()
		}

		return nil
	}
}

func WithSessionMiddleware(store *session.Store) Middleware {
	return func(next fiber.Handler) fiber.Handler {
		return injectSession(store, next)
	}
}

func SessionMiddleware(store *session.Store) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		return nil
	}
}
