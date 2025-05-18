package sessions

import (
	"encoding/gob"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
)

const (
	sessionInfoKey = "info"
)

type SessionInfo struct {
	IP         string
	UserId     uint
	LoginTime  time.Time
	LastSeen   time.Time
	ExpireTime time.Time
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

type SessionStorage struct {
	fiber.Storage
	keyPrefix string
}

func (s *SessionStorage) Set(key string, val []byte, exp time.Duration) error {
	return s.Storage.Set(s.keyPrefix+key, val, exp)
}

func (s *SessionStorage) Get(key string) ([]byte, error) {
	return s.Storage.Get(s.keyPrefix + key)
}

func (s *SessionStorage) Delete(key string) error {
	return s.Storage.Delete(s.keyPrefix + key)
}

func NewSessionStorage(storage fiber.Storage, keyPrefix string) fiber.Storage {
	return &SessionStorage{
		Storage:   storage,
		keyPrefix: keyPrefix,
	}
}

func init() {
	gob.Register(SessionInfo{})
}
