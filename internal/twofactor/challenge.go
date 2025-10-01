package twofactor

import (
	"context"
	"errors"
	"time"

	"github.com/khanghh/cas-go/internal/store"
	"github.com/khanghh/cas-go/params"
)

const (
	ChallengeTypeOTP   = "otp"
	ChallenegeTypeTOTP = "totp"
	ChallengeTypeToken = "token"
)

var (
	ErrChallengeNotFound      = errors.New("challenge not found")
	ErrChallengeInvalid       = errors.New("challenge invalid")
	ErrChallengeExpired       = errors.New("challenge expired")
	ErrTooManyAttemtps        = errors.New("too many attempts")
	ErrContextMismatch        = errors.New("context mismatch")
	ErrOTPRequestLimitReached = errors.New("OTP request limit reached")
	ErrChallengeLimitReached  = errors.New("challenge count limit reached")
)

type ChallengeStatus string

const (
	ChallengeStatusPending ChallengeStatus = "pending"
	ChallengeStatusSuccess ChallengeStatus = "success"
	ChallengeStatusFailed  ChallengeStatus = "failed"
)

type Challenge struct {
	ID           string    `json:"id"           redis:"id"`
	Type         string    `json:"type"         redis:"type"`
	Hash         string    `json:"hash"         redis:"hash"`
	Secret       string    `json:"secret"       redis:"secret"`
	Success      bool      `json:"success"      redis:"success"`
	Attempts     int       `json:"attempts"     redis:"attempts"`
	RefreshCount int       `json:"refreshCount" redis:"refresh_count"`
	RedirectURL  string    `json:"redirectURL"  redis:"redirect_url"`
	ExpiresAt    time.Time `json:"expiresAt"    redis:"expires_at"`
}

func (c *Challenge) IsExpired() bool {
	return c.ExpiresAt.Before(time.Now())
}

func (c *Challenge) CanVerify() bool {
	return !c.IsExpired() && c.Status() == ChallengeStatusPending
}

func (c *Challenge) Status() ChallengeStatus {
	if c.Success {
		return ChallengeStatusSuccess
	}
	if c.Attempts < params.TwoFactorChallengeMaxAttempts {
		return ChallengeStatusPending
	}
	return ChallengeStatusFailed
}

type challengeStore struct {
	store.Store[Challenge]
}

func (s *challengeStore) IncreaseAttempts(ctx context.Context, cid string) (int, error) {
	attempts, err := s.IncrAttr(ctx, cid, "attempts", 1)
	return int(attempts), err
}

func (s *challengeStore) IncreaseRefreshCount(ctx context.Context, cid string) (int, error) {
	refreshCount, err := s.IncrAttr(ctx, cid, "refresh_count", 1)
	return int(refreshCount), err
}

func newChallengeStore(store store.Store[Challenge]) *challengeStore {
	return &challengeStore{
		Store: store,
	}
}
