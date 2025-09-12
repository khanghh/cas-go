package handlers

import (
	"context"

	"github.com/khanghh/cas-go/internal/auth"
	"github.com/khanghh/cas-go/internal/twofactor"
	"github.com/khanghh/cas-go/model"
)

type ServiceRegistry interface {
	RegisterService(ctx context.Context, service *model.Service) (string, error)
	GetService(ctx context.Context, serviceURL string) (*model.Service, error)
}

type AuthorizeService interface {
	ServiceRegistry
	GenerateServiceTicket(ctx context.Context, userID uint, serviceURL string) (*auth.ServiceTicket, error)
	ValidateServiceTicket(ctx context.Context, serviceURL string, ticketId string, timestamp string, signature string) (*auth.ServiceTicket, error)
}

type UserService interface {
	GetUserByID(ctx context.Context, userID uint) (*model.User, error)
	CreateUser(ctx context.Context, user *model.User, rawPassword string) error
	GetUserByUsernameOrEmail(ctx context.Context, identifier string) (*model.User, error)
	GetUserOAuthByID(ctx context.Context, userOAuthID uint) (*model.UserOAuth, error)
	GetOrCreateUserOAuth(ctx context.Context, userOAuth *model.UserOAuth) (*model.UserOAuth, error)
}

type TwoFactorService interface {
	CreateChallenge(opts twofactor.ChallengeOptions) (*twofactor.Challenge, error)
	GetChallenge(cid string) (*twofactor.Challenge, error)
	ValidateChallenge(ch *twofactor.Challenge, binding twofactor.BindingValues) error
	VerifyChallenge(uid uint, ch *twofactor.Challenge, binding twofactor.BindingValues, input string) (twofactor.VerifyResult, error)
	PrepareOTP(uid uint, ch *twofactor.Challenge) (string, error)
}
