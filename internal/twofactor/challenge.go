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
)

type ChallengeStatus string

type Challenge struct {
	ID          string    `json:"id"           redis:"id"`
	Type        string    `json:"type"         redis:"type"`
	Hash        string    `json:"hash"         redis:"hash"`
	Secret      string    `json:"secret"       redis:"secret"`
	Attempts    int       `json:"attempts"     redis:"attempts"`
	RedirectURL string    `json:"redirectURL"  redis:"redirect_url"`
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

func newChallengeStore(store store.Store[Challenge]) *challengeStore {
	return &challengeStore{
		Store: store,
	}
}
