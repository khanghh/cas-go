package oauth

import (
	"context"
	"encoding/json"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	googleOAuthScopeUserInfo = "https://www.googleapis.com/oauth2/v2/userinfo"
)

type GoogleOauthProvider struct {
	name string
	oauth2.Config
}

func (p *GoogleOauthProvider) Name() string {
	return p.name
}

func (p *GoogleOauthProvider) GetOAuthUrl(callbackUrl string, state string) string {
	tmpConfig := p.Config
	tmpConfig.RedirectURL = callbackUrl
	return tmpConfig.AuthCodeURL(state)
}

func (p *GoogleOauthProvider) ExchangeToken(ctx context.Context, code string) (*oauth2.Token, error) {
	return p.Exchange(ctx, code)
}

func (p *GoogleOauthProvider) GetUserInfo(ctx context.Context, token *oauth2.Token) (*OAuthUserInfo, error) {
	var googleUser struct {
		ID            string `json:"id"`
		Name          string `json:"name"`
		FamilyName    string `json:"family_name"`
		GivenName     string `json:"given_name"`
		Picture       string `json:"picture"`
		Email         string `json:"email"`
		VerifiedEmail bool   `json:"verified_email"`
	}
	resp, err := p.Client(ctx, token).Get(googleOAuthScopeUserInfo)
	if err != nil {
		return nil, err
	}
	if err := json.NewDecoder(resp.Body).Decode(&googleUser); err != nil {
		return nil, err
	}
	return &OAuthUserInfo{
		ID:      googleUser.ID,
		Email:   googleUser.Email,
		Name:    googleUser.Name,
		Picture: googleUser.Picture,
	}, nil
}

func NewGoogleOauthProvider(name string, clientId, clientSecret string) *GoogleOauthProvider {
	return &GoogleOauthProvider{
		name: name,
		Config: oauth2.Config{
			ClientID:     clientId,
			ClientSecret: clientSecret,
			Scopes: []string{
				googleOAuthScopeUserInfo,
			},
			Endpoint: google.Endpoint,
		},
	}
}
