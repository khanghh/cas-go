package twofactor

import (
	"context"
	"crypto/rand"
	"math/big"
	"strings"

	"github.com/khanghh/cas-go/params"
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

func (s *OTPChallenger) GenerateOTP(ctx context.Context, ch *Challenge, uid uint) (string, error) {
	otpRequestCount, err := s.svc.userStateStore.IncreaseOTPRequestCount(ctx, uid)
	if err != nil {
		return "", err
	}
	if otpRequestCount > params.TwoFactorUserMaxOTPRequests {
		return "", ErrOTPRequestLimitReached
	}

	otpCode := generateOTP(6)
	ch.Type = ChallengeTypeOTP
	ch.Secret = s.svc.calculateHash(otpCode, otpRequestCount, s.svc.masterKey)
	if err := s.svc.challengeStore.Save(ctx, ch.ID, *ch); err != nil {
		return "", err
	}
	return otpCode, nil
}

func (s *OTPChallenger) VerifyOTP(ctx context.Context, ch *Challenge, userID uint, binding BindingValues, code string) (VerifyResult, error) {
	verifyFunc := func(userState *UserState) (bool, error) {
		return ch.Secret == s.svc.calculateHash(code, userState.OTPRequestCount, s.svc.masterKey), nil
	}
	return s.svc.verifyChallenge(ctx, ch, userID, binding, verifyFunc)
}
