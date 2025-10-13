package twofactor

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/khanghh/cas-go/internal/store"
	"github.com/khanghh/cas-go/params"
)

type TwoFactorService struct {
	userStateStore *userStateStore
	challengeStore *challengeStore
	masterKey      string
}

type Subject struct {
	UserID    uint
	SessionID string
	IPAddress string
	UserAgent string
}

func (s *TwoFactorService) subjectHash(sub Subject) string {
	return s.calculateHash(sub.UserID, sub.SessionID, sub.IPAddress, sub.UserAgent)
}

func (s *TwoFactorService) getStateID(sub Subject) string {
	return s.calculateHash(sub.UserID, sub.IPAddress)
}

func (s *TwoFactorService) calculateHash(inputs ...interface{}) string {
	if len(inputs) == 0 {
		return ""
	}
	h := hmac.New(sha256.New, []byte(s.masterKey))
	for _, val := range inputs {
		switch v := val.(type) {
		case []byte:
			h.Write(v)
		default:
			h.Write([]byte(fmt.Sprintf("%v", v)))
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (s *TwoFactorService) getUserState(ctx context.Context, stateID string) (*UserState, error) {
	userState, err := s.userStateStore.Get(ctx, stateID)
	if errors.Is(err, store.ErrNotFound) {
		userState = &UserState{}
		err = s.userStateStore.Set(ctx, stateID, *userState, params.TwoFactorStateMaxAge)
	}
	if err != nil {
		return nil, err
	}
	return userState, err
}

type ChallengeOptions struct {
	Subject     Subject
	RedirectURL string
	ExpiresIn   time.Duration
}

func (s *TwoFactorService) CreateChallenge(ctx context.Context, opts ChallengeOptions) (*Challenge, error) {
	ch := Challenge{
		ID:          uuid.NewString(),
		Subject:     s.subjectHash(opts.Subject),
		RedirectURL: opts.RedirectURL,
		ExpiresAt:   time.Now().Add(opts.ExpiresIn),
	}

	stateID := s.calculateHash(opts.Subject.UserID, opts.Subject.IPAddress)
	userState, err := s.getUserState(ctx, stateID)
	if err != nil {
		return nil, err
	}
	if userState.FailCount >= params.TwoFactorMaxFailCount {
		return nil, ErrTooManyAttemtps
	}
	userState.ChallengeCount, err = s.userStateStore.IncreaseChallengeCount(ctx, stateID)
	if err != nil {
		return nil, err
	}
	if userState.ChallengeCount > params.TwoFactorMaxChallenges {
		return nil, ErrTooManyAttemtps
	}
	s.userStateStore.ResetChallengeCountAt(ctx, stateID, time.Now().Add(params.TwoFactorChallengeCooldown))

	if err := s.challengeStore.Set(ctx, ch.ID, ch, opts.ExpiresIn); err != nil {
		return nil, err
	}
	return &ch, nil
}

func (s *TwoFactorService) GetChallenge(ctx context.Context, cid string) (*Challenge, error) {
	ch, err := s.challengeStore.Get(ctx, cid)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrChallengeNotFound
	}
	return &ch, err
}

func (s *TwoFactorService) ValidateChallenge(ctx context.Context, ch *Challenge, sub Subject) error {
	if ch.IsExpired() {
		return ErrChallengeExpired
	}
	if ch.Attempts >= params.TwoFactorChallengeMaxAttempts {
		return ErrTooManyAttemtps
	}
	if ch.Subject != s.subjectHash(sub) {
		return ErrSubjectMismatch
	}
	return nil
}

type verifyFunc func(userState *UserState) (bool, error)

func (s *TwoFactorService) verifyChallenge(ctx context.Context, ch *Challenge, sub Subject, doChallengerVerify verifyFunc) error {
	stateID := s.calculateHash(sub.UserID, sub.IPAddress)
	userState, err := s.getUserState(ctx, stateID)
	if err != nil {
		return err
	}

	userState.FailCount, err = s.userStateStore.IncreaseFailCount(ctx, stateID)
	if err != nil {
		return err
	}
	if userState.FailCount > params.TwoFactorMaxFailCount {
		return ErrTooManyAttemtps
	}

	ch.Attempts, err = s.challengeStore.IncreaseAttempts(ctx, ch.ID)
	if err != nil {
		return err
	}
	if ch.Attempts > params.TwoFactorChallengeMaxAttempts {
		return ErrTooManyAttemtps
	}

	success, err := doChallengerVerify(userState)
	if err != nil {
		return err
	}
	if success {
		if err := s.challengeStore.Delete(ctx, ch.ID); err != nil {
			return ErrChallengeExpired
		}
		s.userStateStore.ResetFailCount(ctx, stateID)
		s.userStateStore.DecreaseChallengeCount(ctx, stateID)
		return nil
	}

	attemptsLeft := min(params.TwoFactorChallengeMaxAttempts-ch.Attempts, params.TwoFactorMaxFailCount-userState.FailCount)
	if attemptsLeft == 0 {
		return ErrTooManyAttemtps
	}
	return NewAttemptFailError(attemptsLeft)
}

func (s *TwoFactorService) OTP() *OTPChallenger {
	return &OTPChallenger{s}
}

func (s *TwoFactorService) JWT() *JWTChallenger {
	return &JWTChallenger{s}
}

func (s *TwoFactorService) Token() *TokenChallenger {
	return &TokenChallenger{s}
}

func NewTwoFactorService(storage store.Storage, masterKey string) *TwoFactorService {
	return &TwoFactorService{
		userStateStore: newUserStateStore(storage),
		challengeStore: newChallengeStore(storage),
		masterKey:      masterKey,
	}
}
