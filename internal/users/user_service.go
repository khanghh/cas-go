package users

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/khanghh/cas-go/model"
	"github.com/khanghh/cas-go/model/query"
	"github.com/khanghh/cas-go/params"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gen"
	"gorm.io/gorm"
)

type UserRepository interface {
	WithTx(tx *query.Query) UserRepository
	First(ctx context.Context, conds ...gen.Condition) (*model.User, error)
	Create(ctx context.Context, user *model.User) error
	Updates(ctx context.Context, columns map[string]interface{}, conds ...gen.Condition) (gen.ResultInfo, error)
}

type UserOAuthRepository interface {
	WithTx(tx *query.Query) UserOAuthRepository
	First(ctx context.Context, conds ...gen.Condition) (*model.UserOAuth, error)
	Upsert(ctx context.Context, userOAuth *model.UserOAuth) error
	Find(ctx context.Context, conds ...gen.Condition) ([]*model.UserOAuth, error)
	CreateIfNotExists(ctx context.Context, userOAuth *model.UserOAuth) (*model.UserOAuth, error)
}

type PendingUserRepository interface {
	WithTx(tx *query.Query) PendingUserRepository
	First(ctx context.Context, conds ...gen.Condition) (*model.PendingUser, error)
	Create(ctx context.Context, user *model.PendingUser) error
	Updates(ctx context.Context, columns map[string]interface{}, conds ...gen.Condition) (gen.ResultInfo, error)
	Delete(ctx context.Context, conds ...gen.Condition) (gen.ResultInfo, error)
}

type CreateUserOptions struct {
	Username  string
	FullName  string
	Email     string
	Picture   string
	Password  string
	UserOAuth *model.UserOAuth
}

type UserService struct {
	userRepo        UserRepository
	userOAuthRepo   UserOAuthRepository
	pendingUserRepo PendingUserRepository
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

func (s *UserService) checkUserExist(ctx context.Context, email string, username string) error {
	userQuery := query.User.Where(query.User.Email.Eq(email)).Or(query.User.Username.Eq(username))
	existing, err := s.userRepo.First(ctx, userQuery)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	if existing != nil {
		if existing.Username == username {
			return ErrUsernameTaken
		}
		return ErrEmailRegisterd
	}
	return nil
}

func (s *UserService) checkPendingUserExist(ctx context.Context, email string, username string) error {
	existing, err := s.pendingUserRepo.First(ctx,
		query.PendingUser.Where(query.PendingUser.Email.Eq(email)).Or(query.PendingUser.Username.Eq(username)),
		query.PendingUser.CreatedAt.Gt(time.Now().Add(-params.PendingUserExpiration)),
	)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	if existing != nil {
		if existing.Username == username {
			return ErrUsernameTaken
		}
		return ErrEmailRegisterd
	}
	return nil
}

func (s *UserService) generateVerificationToken() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		panic(fmt.Errorf("failed to generate random bytes: %w", err))
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	return token
}

func (s *UserService) CreateUser(ctx context.Context, opts CreateUserOptions) (*model.User, error) {
	pendingQuery := query.PendingUser.Where(query.PendingUser.Email.Eq(opts.Email)).Or(query.PendingUser.Username.Eq(opts.Username))
	if _, err := s.pendingUserRepo.Delete(ctx, pendingQuery); err != nil {
		return nil, err
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(opts.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	user := model.User{
		Username: opts.Username,
		FullName: opts.FullName,
		Email:    opts.Email,
		Password: string(passwordHash),
		Picture:  opts.Picture,
	}
	if opts.UserOAuth != nil {
		user.OAuths = append(user.OAuths, *opts.UserOAuth)
	}

	var mysqlErr *mysql.MySQLError
	if err := s.userRepo.Create(ctx, &user); errors.As(err, &mysqlErr) && mysqlErr.Number == 1062 {
		switch {
		case strings.Contains(mysqlErr.Message, query.IdxUserUsername):
			return nil, ErrUsernameTaken
		case strings.Contains(mysqlErr.Message, query.IdxUserEmail):
			return nil, ErrEmailRegisterd
		}
	}
	return &user, err
}

func (s *UserService) RegisterUser(ctx context.Context, opts CreateUserOptions) (*model.PendingUser, error) {
	if err := s.checkUserExist(ctx, opts.Email, opts.Username); err != nil {
		return nil, err
	}
	if err := s.checkPendingUserExist(ctx, opts.Email, opts.Username); err != nil {
		return nil, err
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(opts.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	signup := model.PendingUser{
		Username:    opts.Username,
		FullName:    opts.FullName,
		Email:       opts.Email,
		Password:    string(passwordHash),
		Picture:     opts.Picture,
		ActiveToken: s.generateVerificationToken(),
	}

	if err := s.pendingUserRepo.Create(ctx, &signup); err != nil {
		return &signup, err
	}
	return &signup, nil
}

func (s *UserService) ApprovePendingUser(ctx context.Context, email string, token string) (*model.User, error) {
	regUser, err := s.pendingUserRepo.First(ctx,
		query.PendingUser.Email.Eq(email),
		query.PendingUser.ActiveToken.Eq(token),
		query.PendingUser.CreatedAt.Gt(time.Now().Add(-params.PendingUserExpiration)),
	)
	if err != nil {
		return nil, err
	}
	if regUser.ActiveToken != token {
		return nil, ErrInvalidVerificationToken
	}

	updates := map[string]interface{}{
		query.ColPendingUserApproved:  true,
		query.ColPendingUserDeletedAt: time.Now(),
	}
	ret, err := s.pendingUserRepo.Updates(ctx,
		updates,
		query.PendingUser.Email.Eq(email),
		query.PendingUser.ActiveToken.Eq(token),
	)
	if err != nil {
		return nil, err
	}
	if ret.RowsAffected == 0 {
		return nil, ErrPendingUserNotFound
	}

	user := model.User{
		Username: regUser.Username,
		FullName: regUser.FullName,
		Email:    regUser.Email,
		Password: regUser.Password,
		Picture:  regUser.Picture,
	}
	var mysqlErr *mysql.MySQLError
	if err := s.userRepo.Create(ctx, &user); errors.As(err, &mysqlErr) && mysqlErr.Number == 1062 {
		switch {
		case strings.Contains(mysqlErr.Message, query.IdxUserUsername):
			return nil, ErrUsernameTaken
		case strings.Contains(mysqlErr.Message, query.IdxUserEmail):
			return nil, ErrEmailRegisterd
		}
	}
	return &user, err
}

func (s *UserService) GetUserOAuthByID(ctx context.Context, userOAuthID uint) (*model.UserOAuth, error) {
	return s.userOAuthRepo.First(ctx, query.UserOAuth.ID.Eq(userOAuthID))
}

func (s *UserService) GetOrCreateUserOAuth(ctx context.Context, userOAuth *model.UserOAuth) (*model.UserOAuth, error) {
	return s.userOAuthRepo.CreateIfNotExists(ctx, userOAuth)
}

func NewUserService(userRepo UserRepository, userOAuthRepo UserOAuthRepository, pendingUserRepo PendingUserRepository) *UserService {
	return &UserService{
		userRepo:        userRepo,
		userOAuthRepo:   userOAuthRepo,
		pendingUserRepo: pendingUserRepo,
	}
}
