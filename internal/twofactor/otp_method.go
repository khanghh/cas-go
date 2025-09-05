package twofactor

import (
	"crypto/rand"
	"math/big"
	"strings"
	"time"

	"github.com/khanghh/cas-go/params"
)

type OTPMethod struct {
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

func (m *OTPMethod) Create() (*Challenge, string) {
	otpCode := generateOTP(6)
	ch := &Challenge{
		ID:        m.svc.generateChallengeID(),
		Type:      ChallengeTypeOTP,
		Secret:    m.svc.calculateHash(otpCode),
		ExpiresAt: time.Now().Add(time.Minute * 5),
	}
	return ch, otpCode
}

func (m *OTPMethod) Refresh(ch *Challenge) string {
	optCode := generateOTP(6)
	ch.Attempts = 0
	ch.Type = ChallengeTypeOTP
	ch.Secret = m.svc.calculateHash(optCode)
	ch.ExpiresAt = time.Now().Add(time.Minute * 5)
	return optCode
}

func (m *OTPMethod) Verify(ch *Challenge, code string) (int, error) {
	if ch.Attempts >= params.TwoFactorChallengeMaxAttempts {
		return 0, ErrChallengeMaxAttemptsReached
	}
	ch.Attempts++
	ch.Success = ch.Secret == m.svc.calculateHash(code)
	return params.TwoFactorChallengeMaxAttempts - ch.Attempts, nil
}
