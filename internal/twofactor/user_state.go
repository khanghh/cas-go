package twofactor

import (
	"context"
	"time"

	"github.com/khanghh/cas-go/internal/store"
	"github.com/khanghh/cas-go/params"
)

// UserChallengeState keeps track of per user-ip challenge state
type UserChallengeState struct {
	FailCount          int       `redis:"fail_count"`           // total number of failed challenges
	ChallengeCount     int       `redis:"challenge_count"`      // number of pending challenges
	OTPRequestCount    int       `redis:"otp_request_count"`    // total OTP request count
	TOTPVerifiedWindow int       `redis:"totp_verified_window"` // total TOTP verified window
	LockLevel          int       `redis:"lock_level"`
	LockReason         string    `redis:"lock_reason"`
	LockedUntil        time.Time `redis:"locked_until"`
}

func (s *UserChallengeState) CheckLockStatus() *UserLockedError {
	if s.LockedUntil.After(time.Now()) {
		return &UserLockedError{
			Reason: s.LockReason,
			Until:  s.LockedUntil,
		}
	}
	return nil
}

func (s *UserChallengeState) IsLocked() bool {
	return s.LockedUntil.After(time.Now())
}

type userStateStore struct {
	store.Store[UserChallengeState]
}

func (s *userStateStore) Get(ctx context.Context, id string) (*UserChallengeState, error) {
	val, err := s.Store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return &val, err
}

func (s *userStateStore) Set(ctx context.Context, id string, userState UserChallengeState, expiresIn time.Duration) error {
	return s.Store.Set(ctx, id, userState, expiresIn)
}

func (s *userStateStore) Save(ctx context.Context, id string, userState UserChallengeState) error {
	return s.Store.Save(ctx, id, userState)
}

func (s *userStateStore) Del(ctx context.Context, id string) error {
	return s.Store.Delete(ctx, id)
}

func (s *userStateStore) IncreaseFailCount(ctx context.Context, id string) (int, error) {
	failCount, err := s.IncrAttr(ctx, id, "fail_count", 1)
	return int(failCount), err
}

func (s *userStateStore) ResetFailCount(ctx context.Context, id string) (int, error) {
	return 0, s.SetAttr(ctx, id, "fail_count", 0)
}

func (s *userStateStore) IncreaseOTPRequestCount(ctx context.Context, id string) (int, error) {
	otpRequestCount, err := s.IncrAttr(ctx, id, "otp_request_count", 1)
	if err != nil {
		return 0, err
	}
	return int(otpRequestCount), nil
}

func (s *userStateStore) ResetOTPRequestCount(ctx context.Context, id string) (int, error) {
	return 0, s.SetAttr(ctx, id, "otp_request_count", 0)
}

func (s *userStateStore) IncreaseChallengeCount(ctx context.Context, id string) (int, error) {
	failCount, err := s.IncrAttr(ctx, id, "challenge_count", 1)
	return int(failCount), err
}

func (s *userStateStore) DecreaseChallengeCount(ctx context.Context, id string) (int, error) {
	failCount, err := s.IncrAttr(ctx, id, "challenge_count", -1)
	return int(failCount), err
}

func (s *userStateStore) SetChallengeCount(ctx context.Context, id string, count int) error {
	return s.SetAttr(ctx, id, "challenge_count", count)
}

func (s *userStateStore) IncreaseLockLevel(ctx context.Context, id string) (int, error) {
	lockLevel, err := s.IncrAttr(ctx, id, "lock_level", 1)
	return int(lockLevel), err
}

func (s *userStateStore) ResetLockLevel(ctx context.Context, id string) (int, error) {
	return 0, s.SetAttr(ctx, id, "lock_level", 0)
}

func (s *userStateStore) LockUserUntil(ctx context.Context, id string, reason string, until time.Time) error {
	uidKey := id
	err := s.SetAttr(ctx, uidKey, "lock_reason", reason, "locked_until", until)
	if err != nil {
		return err
	}
	return s.ExpireAttr(ctx, uidKey, until, "lock_reason", "locked_until", "fail_count")
}

func (s *userStateStore) SetOTPSentAt(ctx context.Context, id string, sentAt time.Time) error {
	return s.SetAttr(ctx, id, "otp_sent_at", sentAt)
}

func newUserStateStore(storage store.Storage) *userStateStore {
	return &userStateStore{
		Store: store.New[UserChallengeState](storage, params.UserStateKeyPrefix),
	}
}
