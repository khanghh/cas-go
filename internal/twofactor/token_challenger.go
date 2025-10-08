package twofactor

import (
	"context"
	"encoding/json"
	"time"
)

type TokenChallenger struct {
	svc *ChallengeService
}

func (s *TokenChallenger) Generate(ctx context.Context, ch *Challenge, data interface{}) (string, error) {
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
