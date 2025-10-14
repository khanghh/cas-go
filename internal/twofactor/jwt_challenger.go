package twofactor

import (
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenClaims struct {
	Data        interface{} `json:"data,omitempty"`
	ChallengeID string      `json:"cid,omitempty"`
	jwt.RegisteredClaims
}

type JWTChallenger struct {
	svc *TwoFactorService
}

func (s *JWTChallenger) Create(ctx context.Context, subject Subject, redirecrURL string, expiresIn time.Duration, data interface{}) (string, *Challenge, error) {
	ch, err := s.svc.CreateChallenge(ctx, subject, redirecrURL, expiresIn)
	if err != nil {
		return "", nil, err
	}
	token, err := s.Generate(ctx, ch, subject, data)
	if err != nil {
		s.svc.challengeStore.Delete(ctx, ch.ID)
		return "", nil, err
	}
	return token, ch, nil
}

// GenerateToken creates a JWT signed with svc.MasterKey.
func (s *JWTChallenger) Generate(ctx context.Context, ch *Challenge, subject Subject, data interface{}) (string, error) {
	claims := TokenClaims{
		Data:        data,
		ChallengeID: ch.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(ch.ExpiresAt),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(s.svc.masterKey))
	if err != nil {
		return "", err
	}
	ch.Type = ChallengeTypeJWT
	ch.UpdateAt = time.Now()
	if err := s.svc.challengeStore.Save(ctx, ch.ID, *ch); err != nil {
		return "", err
	}
	return signedToken, nil
}

// VerifyToken parses and verifies the JWT using svc.MasterKey
func (s *JWTChallenger) VerifyToken(ctx context.Context, tokenStr string, data interface{}) error {
	claims := TokenClaims{Data: data}
	token, err := jwt.ParseWithClaims(tokenStr, &claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(s.svc.masterKey), nil
	})
	if err != nil {
		return err
	}
	if !token.Valid {
		return ErrTokenInvalid
	}

	if err := s.svc.challengeStore.Delete(ctx, claims.ChallengeID); err != nil {
		return ErrTokenExpired
	}
	return nil
}
