package twofactor

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

type TokenChallenger struct {
	svc *TwoFactorService
}

func (s *TokenChallenger) Create(ctx context.Context, sub Subject, callbackURL string, data interface{}, expiresIn time.Duration) (string, *Challenge, error) {
	blob, err := json.Marshal(data)
	if err != nil {
		return "", nil, err
	}
	ch, err := s.svc.prepareChallenge(ctx, sub, callbackURL)
	if err != nil {
		return "", nil, err
	}
	currentTime := time.Now()
	token := randomSecretKey(32)
	ch.ID = s.svc.calculateHash(token)
	ch.Type = ChallengeTypeToken
	ch.Secret = string(blob)
	ch.UpdateAt = currentTime
	ch.ExpiresAt = currentTime.Add(expiresIn)
	if err := s.svc.challengeStore.Set(ctx, ch.ID, *ch, expiresIn); err != nil {
		return "", nil, err
	}
	return token, ch, nil
}

func (s *TokenChallenger) Generate(ctx context.Context, ch *Challenge, sub Subject, data interface{}) (string, error) {
	return "", fmt.Errorf("not supported")
}

func (s *TokenChallenger) Verify(ctx context.Context, token string, data interface{}) error {
	ch, err := s.svc.challengeStore.Get(ctx, s.svc.calculateHash(token))
	if err != nil {
		return ErrTokenInvalid
	}
	if err := s.svc.challengeStore.Delete(ctx, ch.ID); err != nil {
		return ErrTokenExpired
	}
	return json.Unmarshal([]byte(ch.Secret), data)
}
