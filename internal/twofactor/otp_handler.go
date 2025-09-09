package twofactor

import (
	"crypto/rand"
	"math/big"
	"strings"
)

type OTPHandler struct {
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

func (m *OTPHandler) GenerateOTP(ch *Challenge, salt interface{}) string {
	otpCode := generateOTP(6)
	ch.Type = ChallengeTypeOTP
	ch.Secret = m.svc.calculateHash(otpCode, salt)
	return otpCode
}

func (m *OTPHandler) VerifyOTP(ch *Challenge, code string, salt interface{}) bool {
	return ch.Secret == m.svc.calculateHash(code, salt)
}

func newOTPHandler(svc *TwoFactorService) *OTPHandler {
	return &OTPHandler{
		svc: svc,
	}
}
