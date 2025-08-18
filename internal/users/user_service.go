package users

import (
	"context"
	"errors"
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

func (s *UserService) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	return s.userRepo.First(ctx, query.User.Email.Eq(email))
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
