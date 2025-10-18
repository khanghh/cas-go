package twofactor

import (
	"context"
	"fmt"
	"time"

	"github.com/khanghh/cas-go/model"
	"github.com/pquerna/otp/totp"
)

type TOTPChallenger struct {
	svc *TwoFactorService
}

type TOTPSecret struct {
	Issuer      string `json:"issuer"`
	AccountName string `json:"accountName"`
	Period      uint   `json:"period"`
	Secret      string `json:"secret"`
}

func (s *TOTPChallenger) GenerateSecret() string {
	return randomSecretKey(32)
}

func (s *TOTPChallenger) Enroll(ctx context.Context, userID uint, secret string, code string) error {
	fmt.Println("secret", secret)
	if !totp.Validate(code, secret) {
		return ErrTOTPVerifyFailed
	}
	userFactor := &model.UserFactor{
		UserID:  userID,
		Type:    "totp",
		Secret:  secret,
		Enabled: true,
	}
	return s.svc.userFactorRepo.Upsert(ctx, userFactor)
}

func (s *TOTPChallenger) Create(ctx context.Context, sub Subject, callbackURL string, expiresIn time.Duration) (*Challenge, error) {
	ch, err := s.svc.prepareChallenge(ctx, sub, callbackURL)
	if err != nil {
		return nil, err
	}
	currentTime := time.Now()
	ch.Type = ChallengeTypeTOTP
	ch.UpdateAt = currentTime
	ch.ExpiresAt = currentTime.Add(expiresIn)
	return ch, nil
}

func (c *TOTPChallenger) Generate(ctx context.Context, ch *Challenge, sub Subject) (string, error) {
	return "", fmt.Errorf("not supported")
}

func (c *TOTPChallenger) Verify(ctx context.Context, ch *Challenge, sub Subject, code string) error {
	return c.svc.verifyChallenge(ctx, ch, sub, func(userState *UserState) (bool, error) {
		totpFactor, err := c.svc.userFactorRepo.GetUserFactor(ctx, sub.UserID, "totp")
		if err != nil {
			return false, ErrTOTPNotEnrolled
		}
		return totp.Validate(code, totpFactor.Secret), nil
	})
}
