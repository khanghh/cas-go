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

type ChallengeService struct {
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

func (s *ChallengeService) SubjectHash(sub Subject) string {
	return s.calculateHash(sub.UserID, sub.SessionID, sub.IPAddress, sub.UserAgent)
}

func (s *ChallengeService) calculateHash(inputs ...interface{}) string {
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

func (s *ChallengeService) GetUserState(ctx context.Context, userID uint) (*UserState, error) {
	userState, err := s.userStateStore.Get(ctx, userID)
	if errors.Is(err, store.ErrNotFound) {
		userState = &UserState{UserID: userID}
		err = s.userStateStore.Set(ctx, userID, *userState, params.TwoFactorUserStateMaxAge)
	}
	if err != nil {
		return nil, err
	}
	return userState, err
}

type ChallengeOptions struct {
	Subject
	RedirectURL string
	ExpiresIn   time.Duration
}

func (s *ChallengeService) CreateChallenge(ctx context.Context, opts ChallengeOptions) (*Challenge, error) {
	if opts.UserID != 0 {
		userState, err := s.GetUserState(ctx, opts.UserID)
		if err != nil {
			return nil, err
		}
		if err := userState.CheckLockStatus(); err != nil {
			return nil, err
		}

		userState.ChallengeCount, err = s.userStateStore.IncreaseChallengeCount(ctx, opts.UserID)
		if err != nil {
			return nil, err
		}
		if userState.ChallengeCount > params.TwoFactorUserMaxChallenges {
			return nil, ErrTooManyAttemtps
		}
	}

	ch := Challenge{
		ID:          uuid.NewString(),
		Subject:     s.calculateHash(opts.UserID, opts.SessionID, opts.IPAddress, opts.UserAgent),
		RedirectURL: opts.RedirectURL,
		ExpiresAt:   time.Now().Add(opts.ExpiresIn),
	}
	if err := s.challengeStore.Set(ctx, ch.ID, ch, opts.ExpiresIn); err != nil {
		return nil, err
	}
	return &ch, nil
}

func (s *ChallengeService) GetChallenge(ctx context.Context, cid string) (*Challenge, error) {
	ch, err := s.challengeStore.Get(ctx, cid)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrChallengeNotFound
	}
	return ch, err
}

func (s *ChallengeService) ValidateChallenge(ctx context.Context, ch *Challenge, sub Subject) error {
	if ch.IsExpired() {
		return ErrChallengeExpired
	}
	if ch.Attempts >= params.TwoFactorChallengeMaxAttempts {
		return ErrTooManyAttemtps
	}
	if !ch.CanVerify() {
		return ErrChallengeInvalid
	}
	if ch.Subject != s.SubjectHash(sub) {
		return ErrSubjectMismatch
	}
	return nil
}

func (s *ChallengeService) LockUser(ctx context.Context, userID uint, reason string) (*UserState, error) {
	userState, err := s.GetUserState(ctx, userID)
	if err != nil {
		return nil, err
	}
	var lockDuration time.Duration
	switch userState.LockLevel {
	case 0:
		lockDuration = 1 * time.Minute
	case 1:
		lockDuration = 5 * time.Minute
	case 2:
		lockDuration = 15 * time.Minute
	case 3:
		lockDuration = 1 * time.Hour
	case 4:
		lockDuration = 6 * time.Hour
	default:
		lockDuration = 24 * time.Hour
	}
	userState.LockLevel, err = s.userStateStore.IncreaseLockLevel(ctx, userID)
	if err != nil {
		return nil, err
	}
	userState.LockedUntil = time.Now().Add(lockDuration)
	userState.LockReason = reason
	err = s.userStateStore.LockUserUntil(ctx, userID, userState.LockReason, userState.LockedUntil)
	if err != nil {
		return nil, err
	}
	return userState, nil
}

type verifyFunc func(userState *UserState) (bool, error)

func (s *ChallengeService) verifyChallenge(ctx context.Context, ch *Challenge, sub Subject, doChallengerVerify verifyFunc) error {
	if err := s.ValidateChallenge(ctx, ch, sub); err != nil {
		return err
	}

	userState, err := s.GetUserState(ctx, sub.UserID)
	if err != nil {
		return err
	}
	if err := userState.CheckLockStatus(); err != nil {
		return err
	}

	userState.FailCount, err = s.userStateStore.IncreaseFailCount(ctx, sub.UserID)
	if err != nil {
		return err
	}
	if userState.FailCount > params.TwoFactorUserMaxFailCount {
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
		s.userStateStore.ResetFailCount(ctx, sub.UserID)
		s.userStateStore.ResetLockLevel(ctx, sub.UserID)
		s.userStateStore.DecreaseChallengeCount(ctx, sub.UserID)
		return nil
	}

	if userState.FailCount == params.TwoFactorUserMaxFailCount {
		userState, err = s.LockUser(ctx, sub.UserID, ErrTooManyAttemtps.Error())
		if err != nil {
			return err
		}
		return NewUserLockedError(userState.LockReason, userState.LockedUntil)
	}

	attemptsLeft := min(params.TwoFactorChallengeMaxAttempts-ch.Attempts, params.TwoFactorUserMaxFailCount-userState.FailCount)
	if attemptsLeft == 0 {
		return ErrTooManyAttemtps
	}
	return NewVerifyFailError(attemptsLeft)
}

func (s *ChallengeService) OTP() *OTPChallenger {
	return &OTPChallenger{s}
}

func (s *ChallengeService) JWT() *JWTChallenger {
	return &JWTChallenger{s}
}

func (s *ChallengeService) Token() *TokenChallenger {
	return &TokenChallenger{s}
}

func NewChallengeService(storage store.Storage, masterKey string) *ChallengeService {
	return &ChallengeService{
		userStateStore: newUserStateStore(storage),
		challengeStore: newChallengeStore(storage),
		masterKey:      masterKey,
	}
}
