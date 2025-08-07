package sessions

import (
	"encoding/gob"
	"time"

	"github.com/gofiber/fiber/v2/middleware/session"
)

const (
	sessionInfoKey = "info"
)

type SessionInfo struct {
	IP         string
	UserId     uint
	OAuthId    uint
	LoginTime  time.Time
	LastSeen   time.Time
	ExpireTime time.Time
}

func init() {
	gob.Register(SessionInfo{})
}

type Session struct {
	*session.Session
	SessionInfo
}

func (s *Session) Save(infos ...SessionInfo) error {
	if len(infos) > 0 {
		s.Set(sessionInfoKey, infos[0])
	} else {
		s.Set(sessionInfoKey, s.SessionInfo)
	}
	return s.Session.Save()
}
