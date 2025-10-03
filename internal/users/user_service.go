package users

import (
	"context"
	"errors"
	"net/mail"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/khanghh/cas-go/internal/repository"
	"github.com/khanghh/cas-go/internal/store"
	"github.com/khanghh/cas-go/model"
	"github.com/khanghh/cas-go/model/query"
	"github.com/khanghh/cas-go/params"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type UserService struct {
	userRepo      repository.UserRepository
	userOAuthRepo repository.UserOAuthRepository
	pendingStore  store.Store[model.User]
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

type CreateUserOptions struct {
	Username  string
	FullName  string
	Email     string
	Picture   string
	Password  string
	UserOAuth *model.UserOAuth
}

func (s *UserService) GetPendingUser(ctx context.Context, email string) (*model.User, error) {
	return s.pendingStore.Get(ctx, email)
}

func (s *UserService) ApprovePendingUser(ctx context.Context, email string) (*model.User, error) {
	pendingUser, err := s.pendingStore.Remove(ctx, email)
	if err != nil {
		return nil, ErrPendingUserNotFound
	}

	pendingUser.EmailVerified = true
	if _, err = s.createUser(ctx, pendingUser); err != nil {
		return nil, err
	}

	return pendingUser, nil
}

func (s *UserService) RegisterUser(ctx context.Context, opts CreateUserOptions) (*model.User, error) {
	userQuery := query.User.Where(query.User.Email.Eq(opts.Email)).Or(query.User.Username.Eq(opts.Username))
	existUser, err := s.userRepo.First(ctx, userQuery)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	if existUser != nil {
		if existUser.Username == opts.Username {
			return nil, ErrUsernameTaken
		}
		return nil, ErrEmailRegisterd
	}

	if _, err = s.pendingStore.Get(ctx, opts.Email); err == nil {
		return nil, ErrEmailRegisterd
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(opts.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	user := model.User{
		Username: opts.Username,
		FullName: opts.FullName,
		Password: string(passwordHash),
		Email:    opts.Email,
		Picture:  opts.Picture,
	}

	// create user with oauth
	if opts.UserOAuth != nil && opts.Email == opts.UserOAuth.Email {
		user.OAuths = append(user.OAuths, *opts.UserOAuth)
		return s.createUser(ctx, &user)
	}

	// create pending registration user
	err = s.pendingStore.Set(ctx, opts.Email, user, params.PendingRegisterMaxAge)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *UserService) createUser(ctx context.Context, user *model.User) (*model.User, error) {
	var mysqlErr *mysql.MySQLError
	err := s.userRepo.Create(ctx, user)
	if errors.As(err, &mysqlErr) && mysqlErr.Number == 1062 {
		switch {
		case strings.Contains(mysqlErr.Message, query.IdxUserUsername):
			return nil, ErrUsernameTaken
		case strings.Contains(mysqlErr.Message, query.IdxUserEmail):
			return nil, ErrEmailRegisterd
		}
	}
	return user, err
}

func (s *UserService) GetUserOAuthByID(ctx context.Context, userOAuthID uint) (*model.UserOAuth, error) {
	return s.userOAuthRepo.First(ctx, query.UserOAuth.ID.Eq(userOAuthID))
}

// CreateUserOAuth create user oauth info if not exists
func (s *UserService) GetOrCreateUserOAuth(ctx context.Context, userOAuth *model.UserOAuth) (*model.UserOAuth, error) {
	return s.userOAuthRepo.CreateIfNotExists(ctx, userOAuth)
}

func NewUserService(userRepo repository.UserRepository, userOAuthRepo repository.UserOAuthRepository, pendingUserStore store.Store[model.User]) *UserService {
	return &UserService{
		userRepo:      userRepo,
		userOAuthRepo: userOAuthRepo,
		pendingStore:  pendingUserStore,
	}
}
