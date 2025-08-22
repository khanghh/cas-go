package handlers

import (
	"context"

	"github.com/khanghh/cas-go/internal/auth"
	"github.com/khanghh/cas-go/model"
)

type ServiceRegistry interface {
	RegisterService(ctx context.Context, service *model.Service) (string, error)
	GetService(ctx context.Context, serviceURL string) (*model.Service, error)
}

type UserService interface {
	GetUserByID(ctx context.Context, userID uint) (*model.User, error)
	CreateUser(ctx context.Context, user *model.User) error
	GetUserByUsernameOrEmail(ctx context.Context, identifier string) (*model.User, error)
	GetUserOAuthByID(ctx context.Context, userOAuthID uint) (*model.UserOAuth, error)
	GetOrCreateUserOAuth(ctx context.Context, userOAuth *model.UserOAuth) (*model.UserOAuth, error)
}

type AuthorizeService interface {
	GenerateServiceTicket(ctx context.Context, userID uint, serviceURL string) (*auth.ServiceTicket, error)
	ValidateServiceTicket(ctx context.Context, serviceURL string, ticketID string, timestamp string, signature string) (bool, error)
}
