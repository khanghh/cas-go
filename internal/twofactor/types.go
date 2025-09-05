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
	ErrChallengeNotFound           = errors.New("challenge not found")
	ErrChallengeInvalid            = errors.New("challenge invalid")
	ErrChallengeExpired            = errors.New("challenge expired")
	ErrChallengeMaxAttemptsReached = errors.New("challenge max attempts reached")
	ErrContextMismatch             = errors.New("context mismatch")
	ErrUserLocked                  = errors.New("user locked")
)

type ChallengeStatus string

const (
	ChallengePending ChallengeStatus = "pending"
	ChallengeSuccess ChallengeStatus = "success"
	ChallengeFailed  ChallengeStatus = "failed"
)

type User2FAState struct {
	UserID             uint      `json:"userID"`
	ChallengeID        string    `json:"challengeID"`           // current challenge ID
	FailCount          int       `json:"failCount"`             // total number of failed challenges
	LockedUntil        time.Time `json:"lockedUntil,omitempty"` // zero-value = not locked
	LockReason         string    `json:"lockReason,omitempty"`  // optional explanation (e.g. "too_many_attempts", "reate_limited")
	OTPRequestCount    int       `json:"otpRequestCount"`       // total OTP request count
	TOTPVerifiedWindow int       `json:"totpVerifiedWindow"`    // total TOTP verified window
}

func (s *User2FAState) IsLocked() bool {
	return s.FailCount >= 10 || !s.LockedUntil.IsZero()
}

func (s *User2FAState) IncreaseFailCount() error {
	s.FailCount++
	if s.FailCount >= params.TwoFactorUserMaxFailChallenges {
		s.LockedUntil = time.Now().Add(24 * time.Hour)
		s.LockReason = "too_many_fails"
	}
	return nil
}

type Challenge struct {
	ID        string    `json:"id"        redis:"id"`
	Type      string    `json:"type"      redis:"type"`
	Hash      string    `json:"hash"      redis:"hash"`
	Secret    string    `json:"secret"    redis:"secret"`
	Success   bool      `json:"success"   redis:"success"`
	Attempts  int       `json:"attempts"  redis:"attempts"`
	ExpiresAt time.Time `json:"expiresAt" redis:"expires_at"`
}

func (c *Challenge) IsExpired() bool {
	return c.ExpiresAt.Before(time.Now())
}

func (c *Challenge) Status() ChallengeStatus {
	if c.Success {
		return ChallengeSuccess
	}
	if c.Attempts < params.TwoFactorChallengeMaxAttempts {
		return ChallengePending
	}
	return ChallengeFailed
}

func (c *Challenge) MatchHash(hash string) bool {
	return c.Hash == hash
}
