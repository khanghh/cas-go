package oauth

import (
	"context"
	"encoding/json"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	googleOAuthScopeUserInfoEmail   = "https://www.googleapis.com/auth/userinfo.email"
	googleOAuthScopeUserInfoProfile = "https://www.googleapis.com/auth/userinfo.profile"
	googleAPIEndpointUserInfo       = "https://www.googleapis.com/oauth2/v2/userinfo"
)

type GoogleOAuthProvider struct {
	oauth2.Config
}

func (p *GoogleOAuthProvider) Name() string {
	return "google"
}

func (p *GoogleOAuthProvider) GetAuthCodeUrl(state string) string {
	return p.AuthCodeURL(state)
}

func (p *GoogleOAuthProvider) ExchangeToken(ctx context.Context, code string) (*oauth2.Token, error) {
	return p.Exchange(ctx, code)
}

func (p *GoogleOAuthProvider) GetUserInfo(ctx context.Context, token *oauth2.Token) (*OAuthUserInfo, error) {
	var googleUser struct {
		ID            string `json:"id"`
		Name          string `json:"name"`
		FamilyName    string `json:"family_name"`
		GivenName     string `json:"given_name"`
		Picture       string `json:"picture"`
		Email         string `json:"email"`
		VerifiedEmail bool   `json:"verified_email"`
	}
	resp, err := p.Client(ctx, token).Get(googleAPIEndpointUserInfo)
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

func NewGoogleOAuthProvider(callbackURL, clientId, clientSecret string) *GoogleOAuthProvider {
	return &GoogleOAuthProvider{
		Config: oauth2.Config{
			RedirectURL:  callbackURL,
			ClientID:     clientId,
			ClientSecret: clientSecret,
			Scopes: []string{
				googleOAuthScopeUserInfoEmail,
				googleOAuthScopeUserInfoProfile,
			},
			Endpoint: google.Endpoint,
		},
	}
}
