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

func (s *UserService) GetUserByID(ctx context.Context, userID uint) (*model.User, error) {
	return s.userRepo.First(ctx, query.User.ID.Eq(userID))
}

func (s *UserService) GetUserOAuthByID(ctx context.Context, userOAuthID uint) (*model.UserOAuth, error) {
	return s.userOAuthRepo.First(ctx, query.UserOAuth.ID.Eq(userOAuthID))
}

func (s *UserService) SetLastLoginTime(ctx context.Context, userId uint, lastLoginTime time.Time) error {
	updates := map[string]interface{}{
		query.ColUserLastLoginAt: lastLoginTime,
	}
	_, err := s.userRepo.Updates(ctx, updates, query.User.ID.Eq(userId))
	return err
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
