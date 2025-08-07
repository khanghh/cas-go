package user

import (
	"context"
	"time"

	"github.com/khanghh/cas-go/internal/repository"
	"github.com/khanghh/cas-go/model"
	"github.com/khanghh/cas-go/model/query"
)

type UserService struct {
	userRepo      repository.UserRepository
	userOAuthRepo repository.UserOAuthRepository
}

func (s *UserService) GetUserById(ctx context.Context, userId uint) (*model.User, error) {
	return s.userRepo.First(ctx, query.User.ID.Eq(userId))
}

func (s *UserService) SetLastLoginTime(ctx context.Context, userId uint, lastLoginTime time.Time) error {
	updates := map[string]interface{}{
		query.ColUserLastLoginAt: lastLoginTime,
	}
	_, err := s.userRepo.Updates(ctx, updates, query.User.ID.Eq(userId))
	return err
}

func (s *UserService) GetUserOAuth(ctx context.Context, providerName string, oauthUserId string) (*model.UserOAuth, error) {
	return s.userOAuthRepo.First(ctx, query.UserOAuth.Provider.Eq(providerName), query.UserOAuth.ProfileId.Eq(oauthUserId))
}

// CreateUserOAuth create user oauth info if not exists
func (s *UserService) GetOrCreateUserOAuth(ctx context.Context, userOAuth *model.UserOAuth) (*model.UserOAuth, error) {
	return s.userOAuthRepo.CreateIfNotExists(ctx, userOAuth)
}

func NewUserService(userRepo repository.UserRepository, userOAuthRepo repository.UserOAuthRepository) *UserService {
	return &UserService{
		userRepo:      userRepo,
		userOAuthRepo: userOAuthRepo,
	}
}
