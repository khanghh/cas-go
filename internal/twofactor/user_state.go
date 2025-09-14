package twofactor

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/khanghh/cas-go/internal/store"
	"github.com/khanghh/cas-go/params"
)

type UserState struct {
	UserID             uint      `json:"userID"`
	FailCount          int       `json:"failCount"             redis:"fail_count"`           // total number of failed challenges
	LockedUntil        time.Time `json:"lockedUntil,omitempty" redis:"locked_until"`         // zero-value = not locked
	LockReason         string    `json:"lockReason,omitempty"  redis:"lock_reason"`          // optional explanation (e.g. "too_many_attempts", "reate_limited")
	ChallengeCount     int       `json:"challengeCount"        redis:"challenge_count"`      // total number of challenges
	OTPRequestCount    int       `json:"otpRequestCount"       redis:"otp_request_count"`    // total OTP request count
	TOTPVerifiedWindow int       `json:"totpVerifiedWindow"    redis:"totp_verified_window"` // total TOTP verified window
}

func (s *UserState) IsLocked() bool {
	return s.FailCount >= 10 || !s.LockedUntil.IsZero()
}

func (s *UserState) IncreaseFailCount() error {
	s.FailCount++
	if s.FailCount >= params.TwoFactorUserMaxFailAttempts {
		s.LockedUntil = time.Now().Add(24 * time.Hour)
		s.LockReason = "too_many_fails"
	}
	return nil
}

type userStateStore struct {
	store.Store[UserState]
}

func (s *userStateStore) Get(ctx context.Context, uid uint) (*UserState, error) {
	uidKey := strconv.Itoa(int(uid))
	userState, err := s.Store.Get(ctx, uidKey)
	if errors.Is(err, store.ErrNotFound) {
		return &UserState{UserID: uid}, nil
	} else if err != nil {
		return nil, err
	}
	userState.UserID = uid
	return userState, nil
}

func (s *userStateStore) Set(ctx context.Context, uid uint, userState UserState, expiresIn time.Duration) error {
	uidKey := strconv.Itoa(int(uid))
	return s.Store.Set(ctx, uidKey, userState, expiresIn)
}

func (s *userStateStore) Save(ctx context.Context, uid uint, userState UserState) error {
	uidKey := strconv.Itoa(int(uid))
	return s.Store.Save(ctx, uidKey, userState)
}

func (s *userStateStore) Del(ctx context.Context, uid uint) error {
	uidKey := strconv.Itoa(int(uid))
	return s.Store.Del(ctx, uidKey)
}

func (s *userStateStore) IncreaseFailCount(ctx context.Context, uid uint) (int, error) {
	uidKey := strconv.Itoa(int(uid))
	failCount, err := s.IncrAttr(ctx, uidKey, "fail_count", 1)
	if err != nil {
		return 0, err
	}
	return int(failCount), nil
}

func newUserStateStore(store store.Store[UserState]) *userStateStore {
	return &userStateStore{
		Store: store,
	}
}
