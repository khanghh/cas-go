package handlers

import (
	"context"
	"time"

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
	GetChallenge(ctx context.Context, cid string) (*twofactor.Challenge, error)
	CreateChallenge(ctx context.Context, sub twofactor.Subject, callbackURL string, expiresIn time.Duration) (*twofactor.Challenge, error)
	ValidateChallenge(ctx context.Context, ch *twofactor.Challenge, sub twofactor.Subject) error
	FinalizeChallenge(ctx context.Context, cid string, sub twofactor.Subject, callbackURL string) error
	OTP() *twofactor.OTPChallenger
	TOTP() *twofactor.TOTPChallenger
	JWT() *twofactor.JWTChallenger
	Token() *twofactor.TokenChallenger
}

type UserService interface {
	GetUserByID(ctx context.Context, userID uint) (*model.User, error)
	CreateUser(ctx context.Context, opts users.CreateUserOptions) (*model.User, error)
	RegisterUser(ctx context.Context, opts users.CreateUserOptions) (*model.PendingUser, error)
	ApprovePendingUser(ctx context.Context, email string, token string) (*model.User, error)
	GetUserByEmail(ctx context.Context, email string) (*model.User, error)
	GetUserByUsernameOrEmail(ctx context.Context, identifier string) (*model.User, error)
	GetUserOAuthByID(ctx context.Context, userOAuthID uint) (*model.UserOAuth, error)
	GetOrCreateUserOAuth(ctx context.Context, userOAuth *model.UserOAuth) (*model.UserOAuth, error)
	UpdatePassword(ctx context.Context, email string, newPassword string) error
}
