package user

import (
	"context"
	"time"

	"github.com/khanghh/cas-go/internal/repository"
	"github.com/khanghh/cas-go/model"
	"github.com/khanghh/cas-go/model/query"
)

type UserService struct {
	userRepo repository.UserRepository
}

func (s *UserService) Register(ctx context.Context, user *model.User) error {
	return nil
}

func (s *UserService) RequestChangeEmail(ctx context.Context, user *model.User) error {
	return nil
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

func NewUserService(userRepo repository.UserRepository) *UserService {
	return &UserService{
		userRepo: userRepo,
	}
}
