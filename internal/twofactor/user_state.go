package twofactor

import (
	"context"
	"time"

	"github.com/khanghh/cas-go/internal/store"
	"github.com/khanghh/cas-go/params"
)

// UserState keeps track of per user-ip challenge state
type UserState struct {
	ID                 string
	FailCount          int `redis:"fail_count"`           // total number of failed challenges
	ChallengeCount     int `redis:"challenge_count"`      // number of pending challenges
	OTPRequestCount    int `redis:"otp_request_count"`    // total OTP request count
	TOTPVerifiedWindow int `redis:"totp_verified_window"` // total TOTP verified window
}

type userStateStore struct {
	store.Store[UserState]
}

func (s *userStateStore) Get(ctx context.Context, id string) (*UserState, error) {
	val, err := s.Store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	val.ID = id
	return &val, err
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

func (s *userStateStore) ResetChallengeCountAt(ctx context.Context, id string, expiresAt time.Time) error {
	return s.ExpireAttr(ctx, id, expiresAt, "challenge_count")
}

func (s *userStateStore) SetChallengeCount(ctx context.Context, id string, count int) error {
	return s.SetAttr(ctx, id, "challenge_count", count)
}

func (s *userStateStore) SetOTPSentAt(ctx context.Context, id string, sentAt time.Time) error {
	return s.SetAttr(ctx, id, "otp_sent_at", sentAt)
}

func (s *userStateStore) SetTOTPVerifiedWindow(ctx context.Context, id string, window int) error {
	return s.SetAttr(ctx, id, "totp_verified_window", window)
}

func newUserStateStore(storage store.Storage) *userStateStore {
	return &userStateStore{
		Store: store.New[UserState](storage, params.UserStateKeyPrefix),
	}
}
