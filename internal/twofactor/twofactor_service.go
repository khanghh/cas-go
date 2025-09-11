package twofactor

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/params"
)

type TwoFactorService struct {
	store     *twoFactorStore
	masterKey string
}

type VerifyResult struct {
	Success      bool
	AttemptsLeft int
	LockedUntil  time.Time
	LockReason   string
}

type TokenClaims map[string]interface{}

type BindingValues []interface{}

func (s *TwoFactorService) generateChallengeID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func (s *TwoFactorService) calculateHash(inputs ...interface{}) string {
	var stringBuilder strings.Builder
	for _, val := range inputs {
		fmt.Fprintf(&stringBuilder, "%v", val)
	}
	h := hmac.New(sha256.New, []byte(s.masterKey))
	h.Write([]byte(stringBuilder.String()))
	return hex.EncodeToString(h.Sum(nil))
}

func (s *TwoFactorService) saveUserChallenge(userState *user2FAState, ch *Challenge) error {
	if err := s.store.SaveChallenge(ch); err != nil {
		return err
	}
	return s.store.SaveUserState(userState)
}

type ChallengeOptions struct {
	UserID      uint
	Binding     BindingValues
	Method      string
	RedirectURL string
	ExpiresIn   time.Duration
}

func (s *TwoFactorService) CreateChallenge(opts ChallengeOptions) (*Challenge, error) {
	userState, err := s.store.GetUserState(opts.UserID)
	if err != nil {
		return nil, err
	}

	if userState.IsLocked() {
		return nil, ErrUserLocked
	}

	ch := &Challenge{
		ID:          s.generateChallengeID(),
		Hash:        s.calculateHash(opts.Binding...),
		RedirectURL: opts.RedirectURL,
		ExpiresAt:   time.Now().Add(opts.ExpiresIn),
	}

	userState.ChallengeCount++
	if err := s.saveUserChallenge(userState, ch); err != nil {
		return nil, err
	}

	return ch, nil
}

func (s *TwoFactorService) GetChallenge(cid string) (*Challenge, error) {
	return s.store.GetChallenge(cid)
}

func (s *TwoFactorService) ValidateChallenge(ch *Challenge, binding BindingValues) error {
	if ch.IsExpired() {
		return ErrChallengeExpired
	}
	if ch.Status() != ChallengeStatusPending {
		return ErrChallengeInvalid
	}
	if ch.Attempts >= params.TwoFactorChallengeMaxAttempts {
		return ErrChallengeTooManyAttempts
	}
	if ch.Hash != s.calculateHash(binding...) {
		return ErrContextMismatch
	}
	return nil
}

func (s *TwoFactorService) VerifyChallenge(uid uint, ch *Challenge, binding BindingValues, input string) (VerifyResult, error) {
	if err := s.ValidateChallenge(ch, binding); err != nil {
		return VerifyResult{}, err
	}

	var result VerifyResult
	userState, err := s.store.GetUserState(uid)
	if err != nil {
		return VerifyResult{}, err
	}
	if userState.IsLocked() {
		result.LockReason = userState.LockReason
		result.LockedUntil = userState.LockedUntil
		return result, nil
	}

	if ch.Type == ChallengeTypeOTP {
		ch.Success = newOTPHandler(s).VerifyOTP(ch, input, fmt.Sprintf("%d", userState.OTPRequestCount))
	} else {
		return VerifyResult{}, ErrChallengeInvalid
	}

	ch.Attempts++
	if ch.Success {
		userState.FailCount = 0
	} else if ch.Status() == ChallengeStatusFailed {
		userState.IncreaseFailCount()
	}

	if err := s.saveUserChallenge(userState, ch); err != nil {
		return VerifyResult{}, err
	}

	return VerifyResult{
		Success:      ch.Success,
		AttemptsLeft: min(params.TwoFactorChallengeMaxAttempts-ch.Attempts, params.TwoFactorUserMaxFailAttempts-userState.FailCount),
		LockedUntil:  userState.LockedUntil,
		LockReason:   userState.LockReason,
	}, nil
}

func (s *TwoFactorService) PrepareOTP(uid uint, ch *Challenge) (string, error) {
	userState, err := s.store.GetUserState(uid)
	if err != nil {
		return "", err
	}
	if userState.IsLocked() {
		return "", ErrUserLocked
	}
	if userState.OTPRequestCount >= params.TwoFactorUserMaxOTPRequests {
		return "", ErrOTPRequestLimitReached
	}

	userState.OTPRequestCount++
	otpCode := newOTPHandler(s).GenerateOTP(ch, userState.OTPRequestCount)
	if err := s.saveUserChallenge(userState, ch); err != nil {
		return "", err
	}
	return otpCode, nil
}

func NewTwoFactorService(storage fiber.Storage, masterKey string) *TwoFactorService {
	return &TwoFactorService{
		store:     newTwoFactorStore(storage),
		masterKey: masterKey,
	}
}
