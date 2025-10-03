package twofactor

import (
	"context"
	"errors"

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
func (h *JWTChallenger) GenerateToken(ctx context.Context, ch *Challenge, data interface{}) (string, error) {
	claims := TokenClaims{
		Data:        data,
		ChallengeID: ch.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(ch.ExpiresAt),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(h.svc.masterKey))
	if err != nil {
		return "", err
	}
	ch.Type = ChallengeTypeToken
	return signedToken, nil
}

// VerifyToken parses and verifies the JWT using svc.MasterKey
func (h *JWTChallenger) VerifyToken(ctx context.Context, tokenStr string, data interface{}) error {
	claims := TokenClaims{Data: data}
	token, err := jwt.ParseWithClaims(tokenStr, &claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(h.svc.masterKey), nil
	})
	if err != nil {
		return err
	}
	if !token.Valid {
		return ErrTokenInvalid
	}

	if err := h.svc.challengeStore.Del(ctx, claims.ChallengeID); err != nil {
		return ErrTokenExpired
	}
	return nil
}
