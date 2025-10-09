package twofactor

import (
	"context"
	"strconv"
	"time"

	"github.com/khanghh/cas-go/internal/store"
	"github.com/khanghh/cas-go/params"
)

type UserState struct {
	UserID             uint
	FailCount          int       `redis:"fail_count"`           // total number of failed challenges
	ChallengeCount     int       `redis:"challenge_count"`      // number of pending challenges
	OTPRequestCount    int       `redis:"otp_request_count"`    // total OTP request count
	TOTPVerifiedWindow int       `redis:"totp_verified_window"` // total TOTP verified window
	LockLevel          int       `redis:"lock_level"`
	LockReason         string    `redis:"lock_reason"`
	LockedUntil        time.Time `redis:"locked_until"`
}

func (s *UserState) CheckLockStatus() *UserLockedError {
	if s.LockedUntil.After(time.Now()) {
		return &UserLockedError{
			Reason: s.LockReason,
			Until:  s.LockedUntil,
		}
	}
	return nil
}

func (s *UserState) IsLocked() bool {
	return s.LockedUntil.After(time.Now())
}

type userStateStore struct {
	store.Store[UserState]
}

func (s *userStateStore) Get(ctx context.Context, uid uint) (*UserState, error) {
	return s.Store.Get(ctx, strconv.Itoa(int(uid)))
}

func (s *userStateStore) Set(ctx context.Context, uid uint, userState UserState, expiresIn time.Duration) error {
	return s.Store.Set(ctx, strconv.Itoa(int(uid)), userState, expiresIn)
}

func (s *userStateStore) Save(ctx context.Context, uid uint, userState UserState) error {
	return s.Store.Save(ctx, strconv.Itoa(int(uid)), userState)
}

func (s *userStateStore) Del(ctx context.Context, uid uint) error {
	return s.Store.Delete(ctx, strconv.Itoa(int(uid)))
}

func (s *userStateStore) IncreaseFailCount(ctx context.Context, uid uint) (int, error) {
	failCount, err := s.IncrAttr(ctx, strconv.Itoa(int(uid)), "fail_count", 1)
	return int(failCount), err
}

func (s *userStateStore) ResetFailCount(ctx context.Context, uid uint) (int, error) {
	return 0, s.SetAttr(ctx, strconv.Itoa(int(uid)), "fail_count", 0)
}

func (s *userStateStore) IncreaseOTPRequestCount(ctx context.Context, uid uint) (int, error) {
	otpRequestCount, err := s.IncrAttr(ctx, strconv.Itoa(int(uid)), "otp_request_count", 1)
	if err != nil {
		return 0, err
	}
	return int(otpRequestCount), nil
}

func (s *userStateStore) ResetOTPRequestCount(ctx context.Context, uid uint) (int, error) {
	return 0, s.SetAttr(ctx, strconv.Itoa(int(uid)), "otp_request_count", 0)
}

func (s *userStateStore) IncreaseChallengeCount(ctx context.Context, uid uint) (int, error) {
	failCount, err := s.IncrAttr(ctx, strconv.Itoa(int(uid)), "challenge_count", 1)
	return int(failCount), err
}

func (s *userStateStore) DecreaseChallengeCount(ctx context.Context, uid uint) (int, error) {
	failCount, err := s.IncrAttr(ctx, strconv.Itoa(int(uid)), "challenge_count", -1)
	return int(failCount), err
}

func (s *userStateStore) SetChallengeCount(ctx context.Context, uid uint, count int) error {
	return s.SetAttr(ctx, strconv.Itoa(int(uid)), "challenge_count", count)
}

func (s *userStateStore) IncreaseLockLevel(ctx context.Context, uid uint) (int, error) {
	lockLevel, err := s.IncrAttr(ctx, strconv.Itoa(int(uid)), "lock_level", 1)
	return int(lockLevel), err
}

func (s *userStateStore) ResetLockLevel(ctx context.Context, uid uint) (int, error) {
	return 0, s.SetAttr(ctx, strconv.Itoa(int(uid)), "lock_level", 0)
}

func (s *userStateStore) LockUserUntil(ctx context.Context, uid uint, reason string, until time.Time) error {
	uidKey := strconv.Itoa(int(uid))
	err := s.SetAttr(ctx, uidKey, "lock_reason", reason, "locked_until", until)
	if err != nil {
		return err
	}
	return s.ExpireAttr(ctx, uidKey, until, "lock_reason", "locked_until", "fail_count")
}

func (s *userStateStore) SetOTPSentAt(ctx context.Context, uid uint, sentAt time.Time) error {
	return s.SetAttr(ctx, strconv.Itoa(int(uid)), "otp_sent_at", sentAt)
}

func newUserStateStore(storage store.Storage) *userStateStore {
	return &userStateStore{
		Store: store.New[UserState](storage, params.UserStateStoreKeyPrefix),
	}
}
