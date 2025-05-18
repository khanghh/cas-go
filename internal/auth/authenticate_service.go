package auth

import (
	"context"
	"fmt"

	"github.com/khanghh/cas-go/internal/repository"
	"github.com/khanghh/cas-go/model"
	"github.com/khanghh/cas-go/model/query"
)

type AuthenticateService struct {
	userRepo       repository.UserRepository
	oauthRepo      repository.OAuthRepository
	oauthProviders []OAuthProvider
}

func (s *AuthenticateService) getOAuthProvider(name string) OAuthProvider {
	for _, provider := range s.oauthProviders {
		if provider.Name() == name {
			return provider
		}
	}
	return nil
}

func (s *AuthenticateService) PasswordLogin(ctx context.Context, userName string, password string) (*model.User, error) {
	return nil, nil
}

func (s *AuthenticateService) OAuthProviders() []OAuthProvider {
	return s.oauthProviders
}

func (s *AuthenticateService) CreateUser(ctx context.Context, user *model.User) (*model.User, error) {
	return nil, nil
}

func (s *AuthenticateService) LinkUserOAuth(ctx context.Context, user *model.User, userOAuth *model.UserOAuth) error {
	return nil
}

func (s *AuthenticateService) OAuthLogin(ctx context.Context, userOAuth *model.UserOAuth) (*model.User, error) {
	return nil, nil
}

func (s *AuthenticateService) GetUserByID(ctx context.Context, userID uint) (*model.User, error) {
	return s.userRepo.First(ctx, query.User.ID.Eq(userID))
}

func (s *AuthenticateService) GetUserOAuth(ctx context.Context, providerName string, authCode string) (*model.UserOAuth, error) {
	provider := s.getOAuthProvider(providerName)
	if provider == nil {
		return nil, fmt.Errorf("unknown OAuth provider: %s", providerName)
	}
	token, err := provider.ExchangeToken(ctx, authCode)
	if err != nil {
		return nil, err
	}
	oauthInfo, err := provider.GetUserInfo(ctx, token)
	if err != nil {
		return nil, err
	}

	userOAuth := model.UserOAuth{
		OAuthId:  oauthInfo.ID,
		Provider: providerName,
		Email:    oauthInfo.Email,
		Name:     oauthInfo.Name,
		Picture:  oauthInfo.Picture,
	}
	if err := s.oauthRepo.Upsert(ctx, &userOAuth); err != nil {
		return nil, err
	}
	return &userOAuth, nil
}

func NewAuthenticateService(userRepo repository.UserRepository, oauthRepo repository.OAuthRepository, oauthProviders []OAuthProvider) *AuthenticateService {
	return &AuthenticateService{
		userRepo:       userRepo,
		oauthRepo:      oauthRepo,
		oauthProviders: oauthProviders,
	}
}
