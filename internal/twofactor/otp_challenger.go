package twofactor

import (
	"context"
	"crypto/rand"
	"math/big"
	"strings"
	"time"

	"github.com/khanghh/cas-go/params"
)

type OTPChallenger struct {
	svc *TwoFactorService
}

func generateOTP(length int) string {
	var b strings.Builder
	b.Grow(length)
	ten := big.NewInt(10)
	for i := 0; i < length; i++ {
		n, _ := rand.Int(rand.Reader, ten)
		b.WriteByte(byte('0' + n.Int64()))
	}
	return b.String()
}

func (s *OTPChallenger) Generate(ctx context.Context, ch *Challenge) (string, error) {
	userState, err := s.svc.getChallengeState(ctx, ch.StateID)
	if err != nil {
		return "", err
	}
	if userState.FailCount > params.TwoFactorMaxFailCount {
		return "", ErrTooManyAttemtps
	}
	if time.Since(ch.UpdateAt) < params.TwoFactorOTPRefreshCooldown {
		return "", ErrOTPRequestRateLimited
	}

	userState.OTPRequestCount, err = s.svc.userStateStore.IncreaseOTPRequestCount(ctx, ch.StateID)
	if err != nil {
		return "", err
	}
	if userState.OTPRequestCount > params.TwoFactorMaxOTPRequests {
		return "", ErrOTPRequestLimitReached
	}

	otpCode := generateOTP(6)
	ch.Type = ChallengeTypeOTP
	ch.Secret = s.svc.calculateHash(otpCode, userState.OTPRequestCount, s.svc.masterKey)
	ch.UpdateAt = time.Now()
	if err := s.svc.challengeStore.Save(ctx, ch.ID, *ch); err != nil {
		return "", err
	}
	return otpCode, nil
}

func (s *OTPChallenger) Verify(ctx context.Context, ch *Challenge, subject Subject, code string) error {
	verifyFunc := func(userState *UserState) (bool, error) {
		success := ch.Secret == s.svc.calculateHash(code, userState.OTPRequestCount, s.svc.masterKey)
		if success {
			if time.Since(ch.UpdateAt) > params.TwoFactorOTPExpiration {
				return false, ErrOTPCodeExpired
			}
			stateID := s.svc.getStateID(subject)
			s.svc.userStateStore.ResetOTPRequestCount(ctx, stateID)
		}
		return success, nil
	}
	return s.svc.verifyChallenge(ctx, ch, subject, verifyFunc)
}
