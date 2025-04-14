package repositories

import (
	"context"

	"github.com/khanghh/cas-go/model"
	"github.com/khanghh/cas-go/model/query"
	"gorm.io/gen"
)

type UserRepository interface {
	Create(ctx context.Context, user *model.User) error
	First(ctx context.Context, conds ...gen.Condition) (*model.User, error)
	WithTx(tx *query.Query) UserRepository
}

type userRepository struct {
	query *query.Query
}

func (r *userRepository) First(ctx context.Context, conds ...gen.Condition) (*model.User, error) {
	return nil, nil
}

func (r *userRepository) Create(ctx context.Context, user *model.User) error {
	return r.query.User.WithContext(ctx).Create(user)
}

func (r *userRepository) WithTx(tx *query.Query) UserRepository {
	return NewUserRepository(tx)
}

func NewUserRepository(query *query.Query) UserRepository {
	return &userRepository{query}
}
