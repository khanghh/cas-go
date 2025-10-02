package twofactor

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"strings"

	"github.com/khanghh/cas-go/params"
)

var (
	ErrOTPRequestLimitReached = errors.New("OTP request limit reached")
)

type OTPChallenger struct {
	svc *TwofactorService
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

func (s *OTPChallenger) Generate(ctx context.Context, ch *Challenge, uid uint) (string, error) {
	userState, err := s.svc.getUserState(ctx, uid)
	if err != nil {
		return "", err
	}
	if err := userState.CheckLockStatus(); err != nil {
		return "", err
	}

	userState.OTPRequestCount, err = s.svc.userStateStore.IncreaseOTPRequestCount(ctx, uid)
	if err != nil {
		return "", err
	}
	if userState.OTPRequestCount > params.TwoFactorUserMaxOTPRequests {
		return "", ErrOTPRequestLimitReached
	}

	otpCode := generateOTP(6)
	ch.Type = ChallengeTypeOTP
	ch.Secret = s.svc.calculateHash(otpCode, userState.OTPRequestCount, s.svc.masterKey)
	if err := s.svc.challengeStore.Save(ctx, ch.ID, *ch); err != nil {
		return "", err
	}
	return otpCode, nil
}

func (s *OTPChallenger) Verify(ctx context.Context, ch *Challenge, userID uint, binding BindingValues, code string) (bool, int, error) {
	verifyFunc := func(userState *UserState) (bool, error) {
		success := ch.Secret == s.svc.calculateHash(code, userState.OTPRequestCount, s.svc.masterKey)
		if success {
			s.svc.userStateStore.ResetOTPRequestCount(ctx, userID)
		}
		return success, nil
	}
	return s.svc.verifyChallenge(ctx, ch, userID, binding, verifyFunc)
}
