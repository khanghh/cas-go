package users

import (
	"context"
	"errors"
	"net/mail"
	"strings"

	"github.com/go-sql-driver/mysql"
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

func (s *UserService) GetUserByUsernameOrEmail(ctx context.Context, identifier string) (*model.User, error) {
	if _, err := mail.ParseAddress(identifier); err == nil {
		return s.userRepo.First(ctx, query.User.Email.Eq(identifier))
	}
	return s.userRepo.First(ctx, query.User.Username.Eq(identifier))
}

func (s *UserService) CreateUser(ctx context.Context, user *model.User) error {
	err := s.userRepo.Create(ctx, user)
	var mysqlErr *mysql.MySQLError
	if errors.As(err, &mysqlErr) && mysqlErr.Number == 1062 {
		switch {
		case strings.Contains(mysqlErr.Message, query.IdxUserUsername):
			return ErrUserNameExists
		case strings.Contains(mysqlErr.Message, query.IdxUserEmail):
			return ErrUserEmailExists
		}
	}
	return err
}

func (s *UserService) GetUserOAuthByID(ctx context.Context, userOAuthID uint) (*model.UserOAuth, error) {
	return s.userOAuthRepo.First(ctx, query.UserOAuth.ID.Eq(userOAuthID))
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
