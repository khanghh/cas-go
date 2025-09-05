package twofactor

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
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

func (s *TwoFactorService) OTP() *OTPMethod {
	return &OTPMethod{s}
}

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

func (s *TwoFactorService) CalculateBindingHash(binding BindingValues) string {
	return s.calculateHash(binding...)
}

func (s *TwoFactorService) GetUserState(uid uint) User2FAState {
	state, err := s.store.GetUserState(uid)
	if err != nil {
		return User2FAState{}
	}
	return *state
}

func (s *TwoFactorService) GetChallenge(cid string) (*Challenge, error) {
	return s.store.GetChallenge(cid)
}

func (s *TwoFactorService) VerifyChallenge(uid uint, cid string, binding BindingValues, input string) (VerifyResult, error) {
	ch, err := s.store.GetChallenge(cid)
	if err != nil {
		slog.Debug("challenge not found", "cid", cid)
		return VerifyResult{}, ErrChallengeNotFound
	}

	if ch.Status() != ChallengePending {
		return VerifyResult{}, ErrChallengeInvalid
	}
	if ch.IsExpired() {
		return VerifyResult{}, ErrChallengeExpired
	}
	if ch.MatchHash(s.CalculateBindingHash(binding)) {
		return VerifyResult{}, ErrContextMismatch
	}

	var result VerifyResult
	userState := s.GetUserState(uid)
	if userState.IsLocked() {
		result.LockReason = userState.LockReason
		result.LockedUntil = userState.LockedUntil
		return result, nil
	}

	var attempLeft int
	if ch.Type == ChallengeTypeOTP {
		attempLeft, err = s.OTP().Verify(ch, input)
		if err != nil {
			return VerifyResult{}, err
		}
	}

	if ch.Success {
		userState.ChallengeID = ""
		userState.FailCount = 0
	} else if ch.Status() == ChallengeFailed {
		userState.ChallengeID = ""
		userState.IncreaseFailCount()
	}

	if err := s.saveUserChallenge(&userState, ch); err != nil {
		return VerifyResult{}, err
	}

	return VerifyResult{
		Success:      ch.Success,
		AttemptsLeft: attempLeft,
		LockedUntil:  userState.LockedUntil,
		LockReason:   userState.LockReason,
	}, nil
}

func (s *TwoFactorService) saveUserChallenge(userState *User2FAState, ch *Challenge) error {
	if err := s.store.SaveChallenge(ch); err != nil {
		return err
	}
	return s.store.SaveUserState(userState)
}

func (s *TwoFactorService) SetUserChallenge(uid uint, ch *Challenge, binding BindingValues) error {
	ch.Hash = s.calculateHash(binding)
	if err := s.store.SaveChallenge(ch); err != nil {
		return err
	}

	userState, err := s.store.GetUserState(uid)
	if err != nil {
		return err
	}
	if userState.ChallengeID != "" {
		userState.IncreaseFailCount()
	}
	if ch.Type == ChallengeTypeOTP {
		userState.OTPRequestCount++
	}
	userState.ChallengeID = ch.ID
	return s.store.SaveUserState(userState)
}

func NewTwoFactorService(storage fiber.Storage, masterKey string) *TwoFactorService {
	return &TwoFactorService{
		store:     newTwoFactorStore(storage),
		masterKey: masterKey,
	}
}
