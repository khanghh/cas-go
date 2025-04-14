package services

import "github.com/khanghh/cas-go/internal/repositories"

type AuthService struct {
}

func NewAuthService(userRepo *repositories.UserRepository) *AuthService {
	return &AuthService{}
}
