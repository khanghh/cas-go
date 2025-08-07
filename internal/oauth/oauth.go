package oauth

import (
	"context"

	"golang.org/x/oauth2"
)

const (
	stateEncryptionKey = "secretKey"
)

type OAuthToken = oauth2.Token

type OAuthUserInfo struct {
	ID      string
	Email   string
	Name    string
	Picture string
}

type OAuthProvider interface {
	Name() string
	GetAuthCodeUrl(state string) string
	ExchangeToken(ctx context.Context, code string) (*OAuthToken, error)
	GetUserInfo(ctx context.Context, token *OAuthToken) (*OAuthUserInfo, error)
}
