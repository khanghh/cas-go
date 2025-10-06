package users

import (
	"context"

	"github.com/khanghh/cas-go/model"
	"github.com/khanghh/cas-go/model/query"
	"gorm.io/gen"
)

type userRepository struct {
	query *query.Query
}

func (r *userRepository) First(ctx context.Context, conds ...gen.Condition) (*model.User, error) {
	return r.query.User.WithContext(ctx).Where(conds...).First()
}

func (r *userRepository) Create(ctx context.Context, user *model.User) error {
	return r.query.User.WithContext(ctx).Create(user)
}

func (r *userRepository) Updates(ctx context.Context, columns map[string]interface{}, conds ...gen.Condition) (gen.ResultInfo, error) {
	return r.query.User.WithContext(ctx).Where(conds...).Updates(columns)
}

func (r *userRepository) WithTx(tx *query.Query) UserRepository {
	return NewUserRepository(tx)
}

func NewUserRepository(query *query.Query) UserRepository {
	return &userRepository{query}
}
