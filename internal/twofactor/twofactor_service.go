package twofactor

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/khanghh/cas-go/internal/store"
	"github.com/khanghh/cas-go/params"
)

type TwofactorService struct {
	userStateStore *userStateStore
	challengeStore *challengeStore
	masterKey      string
}

type VerifyResult struct {
	Success      bool
	AttemptsLeft int
	LockReason   string
	LockedUntil  time.Time
}

type BindingValues []interface{}

func (s *TwofactorService) generateChallengeID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func (s *TwofactorService) calculateHash(inputs ...interface{}) string {
	if len(inputs) == 0 {
		return ""
	}
	var stringBuilder strings.Builder
	for _, val := range inputs {
		fmt.Fprintf(&stringBuilder, "%v", val)
	}
	h := hmac.New(sha256.New, []byte(s.masterKey))
	h.Write([]byte(stringBuilder.String()))
	return hex.EncodeToString(h.Sum(nil))
}

func (s *TwofactorService) saveUserAndChallenge(ctx context.Context, userState *UserState, ch *Challenge) error {
	err := s.challengeStore.Save(ctx, ch.ID, *ch)
	if err != nil {
		return err
	}
	return s.userStateStore.Save(ctx, userState.UserID, *userState)
}

type ChallengeOptions struct {
	UserID      uint
	Binding     BindingValues
	RedirectURL string
	ExpiresIn   time.Duration
}

func (s *TwofactorService) CreateChallenge(ctx context.Context, opts ChallengeOptions) (*Challenge, error) {
	challengeCount, err := s.userStateStore.IncreaseChallengeCount(ctx, opts.UserID)
	if err != nil {
		return nil, err
	}
	if challengeCount > params.TwoFactorUserMaxFailCount {
		s.userStateStore.SetChallengeCount(ctx, opts.UserID, params.TwoFactorUserMaxFailCount)
		return nil, ErrChallengeLimitReached
	}

	ch := Challenge{
		ID:          s.generateChallengeID(),
		Hash:        s.calculateHash(opts.Binding...),
		RedirectURL: opts.RedirectURL,
		ExpiresAt:   time.Now().Add(opts.ExpiresIn),
	}

	err = s.challengeStore.Set(ctx, ch.ID, ch, opts.ExpiresIn)
	if err != nil {
		return nil, err
	}
	return &ch, nil
}

func (s *TwofactorService) GetChallenge(ctx context.Context, cid string) (*Challenge, error) {
	return s.challengeStore.Get(ctx, cid)
}

func (s *TwofactorService) ValidateChallenge(ctx context.Context, ch *Challenge, binding BindingValues) error {
	if ch.IsExpired() {
		return ErrChallengeExpired
	}
	if ch.Attempts >= params.TwoFactorChallengeMaxAttempts {
		return ErrTooManyAttemtps
	}
	if ch.Status() != ChallengeStatusPending {
		return ErrChallengeInvalid
	}
	if ch.Hash != s.calculateHash(binding...) {
		return ErrContextMismatch
	}
	return nil
}

func (s *TwofactorService) GetUserState(ctx context.Context, uid uint) (*UserState, error) {
	return s.userStateStore.Get(ctx, uid)
}

func (s *TwofactorService) LockUser(ctx context.Context, userID uint, reason string) (time.Duration, error) {
	lockLevel, err := s.userStateStore.IncreaseLockLevel(ctx, userID)
	if err != nil {
		return 0, err
	}
	var lockDuration time.Duration
	switch lockLevel {
	case 1:
		lockDuration = 1 * time.Minute
	case 2:
		lockDuration = 5 * time.Minute
	case 3:
		lockDuration = 15 * time.Minute
	case 4:
		lockDuration = 1 * time.Hour
	case 5:
		lockDuration = 6 * time.Hour
	default:
		lockDuration = 24 * time.Hour
	}
	return lockDuration, s.userStateStore.LockUser(ctx, userID, reason, lockDuration)
}

type verifyFunc func(userState *UserState) (bool, error)

func (s *TwofactorService) verifyChallenge(ctx context.Context, ch *Challenge, userID uint, binding BindingValues, doChallengerVerify verifyFunc) (VerifyResult, error) {
	if err := s.ValidateChallenge(ctx, ch, binding); err != nil {
		return VerifyResult{}, err
	}

	userState, err := s.userStateStore.Get(ctx, userID)
	if err != nil {
		return VerifyResult{}, err
	}
	if userState.IsLocked() {
		return VerifyResult{
			LockReason:  userState.LockReason,
			LockedUntil: userState.LockedUntil,
		}, nil
	}

	userState.FailCount, err = s.userStateStore.IncreaseFailCount(ctx, userID)
	if err != nil {
		return VerifyResult{}, err
	}
	if userState.FailCount > params.TwoFactorUserMaxFailCount {
		return VerifyResult{}, ErrTooManyAttemtps
	}

	ch.Attempts, err = s.challengeStore.IncreaseAttempts(ctx, ch.ID)
	if err != nil {
		return VerifyResult{}, err
	}
	if ch.Attempts > params.TwoFactorChallengeMaxAttempts {
		return VerifyResult{}, ErrTooManyAttemtps
	}

	ch.Success, err = doChallengerVerify(userState)
	if err != nil {
		return VerifyResult{}, err
	}
	if ch.Success {
		if err := s.challengeStore.Del(ctx, ch.ID); err != nil {
			return VerifyResult{}, ErrChallengeExpired
		}
		s.userStateStore.ResetFailCount(ctx, userID)
		return VerifyResult{Success: true}, nil
	}

	if userState.FailCount == params.TwoFactorUserMaxFailCount {
		lockDuration, err := s.LockUser(ctx, userID, ErrTooManyAttemtps.Error())
		if err != nil {
			return VerifyResult{}, err
		}
		return VerifyResult{
			LockReason:  ErrTooManyAttemtps.Error(),
			LockedUntil: time.Now().Add(lockDuration),
		}, ErrTooManyAttemtps
	}

	attemptsLeft := min(params.TwoFactorChallengeMaxAttempts-ch.Attempts, params.TwoFactorUserMaxFailCount-userState.FailCount)
	if attemptsLeft == 0 {
		return VerifyResult{}, ErrTooManyAttemtps
	}
	return VerifyResult{AttemptsLeft: attemptsLeft}, nil
}

func (s *TwofactorService) OTPChallenger() *OTPChallenger {
	return &OTPChallenger{s}
}

func (s *TwofactorService) JWTChallenger() *JWTChallenger {
	return &JWTChallenger{s}
}

func NewTwoFactorService(challengeStore store.Store[Challenge], userStateStore store.Store[UserState], masterKey string) *TwofactorService {
	return &TwofactorService{
		userStateStore: newUserStateStore(userStateStore),
		challengeStore: newChallengeStore(challengeStore),
		masterKey:      masterKey,
	}
}
