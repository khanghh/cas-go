package user

import (
	"context"

	"github.com/khanghh/cas-go/internal/repository"
	"github.com/khanghh/cas-go/model"
)

type UserService struct {
	userRepo *repository.UserRepository
}

func (s *UserService) Register(ctx context.Context, user *model.User) error {
	return nil
}

func (s *UserService) RequestChangeEmail(ctx context.Context, user *model.User) error {
	return nil
}

func NewUserService(userRepo *repository.UserRepository) *UserService {
	return &UserService{
		userRepo: userRepo,
	}
}
