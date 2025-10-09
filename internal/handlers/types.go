package handlers

import (
	"context"

	"github.com/khanghh/cas-go/internal/auth"
	"github.com/khanghh/cas-go/internal/twofactor"
	"github.com/khanghh/cas-go/internal/users"
	"github.com/khanghh/cas-go/model"
)

type ServiceRegistry interface {
	RegisterService(ctx context.Context, service *model.Service) (string, error)
	GetService(ctx context.Context, serviceURL string) (*model.Service, error)
}

type AuthorizeService interface {
	ServiceRegistry
	GenerateServiceTicket(ctx context.Context, userID uint, callbackURL string) (*auth.ServiceTicket, error)
	ValidateServiceTicket(ctx context.Context, serviceURL string, ticketId string, timestamp string, signature string) (*auth.ServiceTicket, error)
}

type TwoFactorService interface {
	GetUserState(ctx context.Context, userID uint) (*twofactor.UserState, error)
	CreateChallenge(ctx context.Context, opts twofactor.ChallengeOptions) (*twofactor.Challenge, error)
	GetChallenge(ctx context.Context, cid string) (*twofactor.Challenge, error)
	ValidateChallenge(ctx context.Context, ch *twofactor.Challenge) error
	LockUser(ctx context.Context, userID uint, reason string) (*twofactor.UserState, error)
	OTP() *twofactor.OTPChallenger
	JWT() *twofactor.JWTChallenger
	Token() *twofactor.TokenChallenger
}

type UserService interface {
	GetUserByID(ctx context.Context, userID uint) (*model.User, error)
	CreateUser(ctx context.Context, opts users.CreateUserOptions) (*model.User, error)
	RegisterUser(ctx context.Context, opts users.CreateUserOptions) (*model.PendingUser, error)
	ApprovePendingUser(ctx context.Context, email string, token string) (*model.User, error)
	GetUserByUsernameOrEmail(ctx context.Context, identifier string) (*model.User, error)
	GetUserOAuthByID(ctx context.Context, userOAuthID uint) (*model.UserOAuth, error)
	GetOrCreateUserOAuth(ctx context.Context, userOAuth *model.UserOAuth) (*model.UserOAuth, error)
}
