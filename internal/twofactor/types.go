package twofactor

import (
	"errors"
	"time"

	"github.com/khanghh/cas-go/params"
)

const (
	ChallengeTypeOTP    = "otp"
	ChallenegeTypeTOTP  = "totp"
	ChallenegeTypeToken = "token"
)

var (
	ErrChallengeNotFound        = errors.New("challenge not found")
	ErrChallengeInvalid         = errors.New("challenge invalid")
	ErrChallengeExpired         = errors.New("challenge expired")
	ErrChallengeTooManyAttempts = errors.New("challenge attempts limit reached")
	ErrContextMismatch          = errors.New("context mismatch")
	ErrUserLocked               = errors.New("user locked")
	ErrTooManyAttempts          = errors.New("too many attempts")
	ErrOTPRequestLimitReached   = errors.New("OTP request limit reached")
)

type ChallengeStatus string

const (
	ChallengeStatusPending ChallengeStatus = "pending"
	ChallengeStatusSuccess ChallengeStatus = "success"
	ChallengeStatusFailed  ChallengeStatus = "failed"
)

type user2FAState struct {
	UserID             uint      `json:"userID"`
	FailCount          int       `json:"failCount"`             // total number of failed challenges
	LockedUntil        time.Time `json:"lockedUntil,omitempty"` // zero-value = not locked
	LockReason         string    `json:"lockReason,omitempty"`  // optional explanation (e.g. "too_many_attempts", "reate_limited")
	ChallengeCount     int       `json:"challengeCount"`        // total number of challenges
	OTPRequestCount    int       `json:"otpRequestCount"`       // total OTP request count
	TOTPVerifiedWindow int       `json:"totpVerifiedWindow"`    // total TOTP verified window
}

func (s *user2FAState) IsLocked() bool {
	return s.FailCount >= 10 || !s.LockedUntil.IsZero()
}

func (s *user2FAState) IncreaseFailCount() error {
	s.FailCount++
	if s.FailCount >= params.TwoFactorUserMaxFailAttempts {
		s.LockedUntil = time.Now().Add(24 * time.Hour)
		s.LockReason = "too_many_fails"
	}
	return nil
}

type Challenge struct {
	ID          string    `json:"id"          redis:"id"`
	Type        string    `json:"type"        redis:"type"`
	Hash        string    `json:"hash"        redis:"hash"`
	Secret      string    `json:"secret"      redis:"secret"`
	Success     bool      `json:"success"     redis:"success"`
	Attempts    int       `json:"attempts"    redis:"attempts"`
	RedirectURL string    `json:"redirectURL" redis:"redirect_url"`
	ExpiresAt   time.Time `json:"expiresAt"   redis:"expires_at"`
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
