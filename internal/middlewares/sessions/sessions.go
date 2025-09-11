package sessions

import (
	"crypto/rand"
	"encoding/gob"
	"encoding/hex"
	"log/slog"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/khanghh/cas-go/params"
)

const (
	injectSessionKey = "session"
	sessionDataKey   = "data"
)

type Middleware func(next fiber.Handler) fiber.Handler

type SessionData struct {
	id          string    // session id
	IP          string    // client ip address
	UserID      uint      // user id
	OAuthID     uint      // user oauth id
	CSRFToken   string    // csrf token
	LastSeen    time.Time // last request time
	LoginTime   time.Time // last login time
	Last2FATime time.Time // last 2fa success time
	ChallengeID string    // current challenge id
	ExpireTime  time.Time // session expire time
}

func (s SessionData) ID() string {
	return s.id
}

func (s *SessionData) IsLoggedIn() bool {
	return s.UserID != 0 && s.LoginTime.Unix() > 0
}

func (s *SessionData) IsRequire2FA() bool {
	return time.Since(s.Last2FATime) > params.TwoFactorValidityDuration
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

func Reset(ctx *fiber.Ctx, data *SessionData) error {
	sess := ctx.Locals(injectSessionKey).(*session.Session)
	err := sess.Reset()
	if err != nil {
		return err
	}
	data.id = sess.ID()
	sess.Set(sessionDataKey, *data)
	return nil
}

func SessionMiddleware(store *session.Store) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		sess, err := store.Get(ctx)
		if err != nil {
			return err
		}

		ctx.Locals(injectSessionKey, sess)
		if err := ctx.Next(); err != nil {
			return err
		}

		data, ok := sess.Get(sessionDataKey).(SessionData)
		if ok {
			data.LastSeen = time.Now()
			sess.Set(sessionDataKey, data)
			return sess.Save()
		}

		return nil
	}
}
