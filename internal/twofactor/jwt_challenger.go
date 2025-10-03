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
	svc *TwofactorService
}

// GenerateToken creates a JWT signed with svc.MasterKey.
func (s *JWTChallenger) GenerateToken(ctx context.Context, ch *Challenge, data interface{}) (string, error) {
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
	ch.Type = ChallengeTypeToken
	ch.UpdateAt = time.Now().UTC()
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

	if err := s.svc.challengeStore.Del(ctx, claims.ChallengeID); err != nil {
		return ErrTokenExpired
	}
	return nil
}
