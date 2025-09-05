package twofactor

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
)

type twoFactorStore struct {
	storage fiber.Storage
}

func (s *twoFactorStore) GetChallenge(cid string) (*Challenge, error) {
	blob, err := s.storage.Get(cid)
	if err != nil {
		return nil, err
	}
	var challenge Challenge
	if err := json.Unmarshal(blob, &challenge); err != nil {
		return nil, err
	}
	return &challenge, nil
}

func (s *twoFactorStore) SaveChallenge(ch *Challenge) error {
	blob, _ := json.Marshal(ch)
	return s.storage.Set(ch.ID, blob, time.Until(ch.ExpiresAt))
}

func (s *twoFactorStore) DeleteChallenge(cid string) error {
	return s.storage.Delete(cid)
}

func (s *twoFactorStore) GetUserState(uid uint) (*User2FAState, error) {
	key := fmt.Sprintf("state:user:%d", uid)
	blob, err := s.storage.Get(key)
	if err != nil {
		return nil, err
	}
	if len(blob) == 0 {
		return &User2FAState{}, nil
	}

	var state User2FAState
	if err := json.Unmarshal(blob, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

func (s *twoFactorStore) SaveUserState(state *User2FAState) error {
	blob, _ := json.Marshal(state)
	key := fmt.Sprintf("state:user:%d", state.UserID)
	return s.storage.Set(key, blob, 24*time.Hour)
}

func newTwoFactorStore(storage fiber.Storage) *twoFactorStore {
	return &twoFactorStore{
		storage: storage,
	}
}
