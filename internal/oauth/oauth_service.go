package oauth

import (
	"context"
	"fmt"

	"github.com/khanghh/cas-go/internal/repository"
	"github.com/khanghh/cas-go/model"
	"github.com/khanghh/cas-go/model/query"
)

type OAuthService struct {
	userRepo           repository.UserRepository
	oauthRepo          repository.OAuthRepository
	oauthProviders     []OAuthProvider
	stateEncryptionKey string
}

func (s *OAuthService) getOAuthProvider(name string) OAuthProvider {
	for _, provider := range s.oauthProviders {
		if provider.Name() == name {
			return provider
		}
	}
	return nil
}

func (s *OAuthService) OAuthProviders() []OAuthProvider {
	return s.oauthProviders
}

func (s *OAuthService) AddUpdateUserOAuth(ctx context.Context, userOAuth *model.UserOAuth) error {
	return s.oauthRepo.Upsert(ctx, userOAuth)
}

func (s *OAuthService) GetUserOAuths(ctx context.Context, userId uint) ([]*model.UserOAuth, error) {
	return s.oauthRepo.Find(ctx, query.UserOAuth.ID.Eq(userId))
}

// CreateUserOAuth fetch user info from OAuth provider and create or update user OAuth info
func (s *OAuthService) GetOrCreateUserOAuth(ctx context.Context, providerName string, authCode string) (*model.UserOAuth, error) {
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

func (o *OAuthService) CreateUserOAuth(ctx context.Context) (*model.UserOAuth, error) {
	panic("TODO: Implement")
}

func NewOAuthService(userRepo repository.UserRepository, oauthRepo repository.OAuthRepository, oauthProviders []OAuthProvider, stateEncryptionKey string) *OAuthService {
	return &OAuthService{
		userRepo:           userRepo,
		oauthRepo:          oauthRepo,
		oauthProviders:     oauthProviders,
		stateEncryptionKey: stateEncryptionKey,
	}
}
