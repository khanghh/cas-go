package twofactor

import (
	"context"
	"encoding/json"
	"time"
)

type TokenChallenger struct {
	svc *TwoFactorService
}

func (s *TokenChallenger) Create(ctx context.Context, sub Subject, redirecrURL string, expiresIn time.Duration, data interface{}) (string, *Challenge, error) {
	ch, err := s.svc.CreateChallenge(ctx, sub, redirecrURL, expiresIn)
	if err != nil {
		return "", nil, err
	}
	token, err := s.Generate(ctx, ch, sub, data)
	if err != nil {
		s.svc.challengeStore.Delete(ctx, ch.ID)
		return "", nil, err
	}
	return token, ch, nil
}

func (s *TokenChallenger) Generate(ctx context.Context, ch *Challenge, sub Subject, data interface{}) (string, error) {
	blob, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	ch.Type = ChallengeTypeToken
	ch.Secret = string(blob)
	ch.UpdateAt = time.Now()
	if err := s.svc.challengeStore.Save(ctx, ch.ID, *ch); err != nil {
		return "", err
	}
	return s.svc.calculateHash(blob, ch.UpdateAt.UnixNano()), nil
}

func (s *TokenChallenger) Verify(ctx context.Context, ch *Challenge, token string, data interface{}) error {
	if ch.Type != ChallengeTypeToken {
		return ErrTokenInvalid
	}
	if token == s.svc.calculateHash([]byte(ch.Secret), ch.UpdateAt.UnixNano()) {
		if err := s.svc.challengeStore.Delete(ctx, ch.ID); err != nil {
			return ErrTokenExpired
		}
		return json.Unmarshal([]byte(ch.Secret), data)
	}
	return ErrTokenInvalid
}
