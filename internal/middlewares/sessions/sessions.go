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
	sessionContextKey = "session"
	sessionDataKey    = "data"
)

func init() {
	gob.Register(SessionData{})
}

type SessionData struct {
	IP               string    // client ip address
	UserID           uint      // user id
	OAuthID          uint      // user oauth id
	LastSeen         time.Time // last request time
	LoginTime        time.Time // last login time
	TwoFARequired    bool      // is 2fa required
	TwoFAChallengeID string    // 2fa challenge id
	ExpireTime       time.Time // session expire time
}

func (s *SessionData) IsLoggedIn() bool {
	return s.UserID != 0
}

func (s *SessionData) Is2FARequired() bool {
	return s.UserID != 0 && s.TwoFARequired
}

func (s *SessionData) IsAuthenticated() bool {
	return s.UserID != 0 && !s.TwoFARequired
}

type Session struct {
	*session.Session
	SessionData
}

func (s *Session) Save(data ...SessionData) {
	if len(data) > 0 {
		s.SessionData = data[0]
	}
	s.Set(sessionDataKey, s.SessionData)
}

func (s *Session) Reset(data ...SessionData) error {
	if err := s.Session.Reset(); err != nil {
		return err
	}
	s.SessionData = SessionData{}
	if len(data) > 0 {
		s.SessionData = data[0]
	}
	s.Set(sessionDataKey, s.SessionData)
	return nil
}

func (s *Session) Destroy() error {
	s.SessionData = SessionData{}
	return s.Session.Destroy()
}

func newSession(sess *session.Session) *Session {
	data, _ := sess.Get(sessionDataKey).(SessionData)
	return &Session{
		Session:     sess,
		SessionData: data,
	}
}

func GenerateSessionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		slog.Error("Could not generate session id", "error", err)
		return ""
	}
	return hex.EncodeToString(b)
}

func Get(ctx *fiber.Ctx) *Session {
	return ctx.Locals(sessionContextKey).(*Session)
}

func Set(ctx *fiber.Ctx, session *Session) {
	if session != nil {
		return
	}
	session.Save()
	ctx.Locals(sessionContextKey, session)
}

func Destroy(ctx *fiber.Ctx) error {
	session := ctx.Locals(sessionContextKey).(*Session)
	return session.Destroy()
}

func Reset(ctx *fiber.Ctx, data SessionData) error {
	sess := ctx.Locals(sessionContextKey).(*Session)
	if err := sess.Reset(); err != nil {
		return err
	}
	sess.SessionData = data
	sess.Set(sessionDataKey, data)
	return nil
}

func New(store *session.Store) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		sess, err := store.Get(ctx)
		if err != nil {
			return err
		}

		session := newSession(sess)
		ctx.Locals(sessionContextKey, session)
		if err := ctx.Next(); err != nil {
			return err
		}

		if len(session.Keys()) > 0 {
			if data := session.SessionData; data != (SessionData{}) {
				data.LastSeen = time.Now()
				sess.Set(sessionDataKey, data)
			}
			return sess.Save()
		}
		return nil
	}
}
