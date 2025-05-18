package sessions

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
)

const (
	sessionContextKey = "session"
)

type Middleware func(next fiber.Handler) fiber.Handler

func GenerateSessionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		slog.Error("Could not generate session id", "error", err)
		return ""
	}
	return hex.EncodeToString(b)
}

func Get(ctx *fiber.Ctx) *Session {
	session, ok := ctx.Locals(sessionContextKey).(*Session)
	if ok {
		return session
	}
	return nil
}

func getFromStore(store *session.Store, ctx *fiber.Ctx) (*Session, error) {
	sess, err := store.Get(ctx)
	if err != nil {
		return nil, err
	}
	sessionInfo, ok := sess.Get(sessionInfoKey).(SessionInfo)
	if ok {
		return &Session{
			Session:     sess,
			SessionInfo: sessionInfo,
		}, nil
	}
	return &Session{Session: sess}, nil
}

func injectSession(store *session.Store, next fiber.Handler) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		session, err := getFromStore(store, ctx)
		if err != nil {
			return err
		}

		ctx.Locals(sessionContextKey, session)
		if err := next(ctx); err != nil {
			return err
		}

		if !session.Fresh() {
			session.LastSeen = time.Now()
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
