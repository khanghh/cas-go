package twofactor

import (
	"context"
	"time"

	"github.com/khanghh/cas-go/internal/store"
	"github.com/khanghh/cas-go/params"
)

const (
	ChallengeTypeOTP   = "otp"
	ChallenegeTypeTOTP = "totp"
	ChallengeTypeToken = "token"
	ChallengeTypeJWT   = "jwt"
)

type ChallengeStatus string

type Challenge struct {
	ID          string    `json:"id"           redis:"id"`
	Type        string    `json:"type"         redis:"type"`
	Subject     string    `json:"subject"      redis:"subject"`
	Secret      string    `json:"secret"       redis:"secret"`
	Attempts    int       `json:"attempts"     redis:"attempts"`
	CallbackURL string    `json:"redirectURL"  redis:"redirect_url"`
	Success     int       `json:"success"      redis:"success"`
	UpdateAt    time.Time `json:"updateAt"     redis:"update_at"`
	ExpiresAt   time.Time `json:"expiresAt"    redis:"expires_at"`
}

func (c *Challenge) IsExpired() bool {
	return c.ExpiresAt.Before(time.Now())
}

func (c *Challenge) CanVerify() bool {
	return !c.IsExpired() && c.Attempts < params.TwoFactorChallengeMaxAttempts
}

type challengeStore struct {
	store.Store[Challenge]
}

func (s *challengeStore) IncreaseAttempts(ctx context.Context, cid string) (int, error) {
	attempts, err := s.IncrAttr(ctx, cid, "attempts", 1)
	return int(attempts), err
}

func (s *challengeStore) MarkSuccess(ctx context.Context, cid string) error {
	count, err := s.IncrAttr(ctx, cid, "success", 1)
	if err != nil {
		return err
	}
	if count == 1 {
		return nil
	}
	return ErrChallengeAlreadyVerified
}

func newChallengeStore(storage store.Storage) *challengeStore {
	return &challengeStore{
		Store: store.New[Challenge](storage, params.ChallengeKeyPrefix),
	}
}
