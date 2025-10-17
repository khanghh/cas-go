package users

import (
	"context"

	"github.com/khanghh/cas-go/model"
	"github.com/khanghh/cas-go/model/query"
	"gorm.io/gen"
)

type PendingUserRepository interface {
	WithTx(tx *query.Query) PendingUserRepository
	First(ctx context.Context, conds ...gen.Condition) (*model.PendingUser, error)
	Create(ctx context.Context, user *model.PendingUser) error
	Updates(ctx context.Context, columns map[string]interface{}, conds ...gen.Condition) (gen.ResultInfo, error)
	Delete(ctx context.Context, conds ...gen.Condition) (gen.ResultInfo, error)
}

type pendingUserRepository struct {
	query *query.Query
}

func (r *pendingUserRepository) WithTx(tx *query.Query) PendingUserRepository {
	return NewPendingUserRepository(tx)
}

func (r *pendingUserRepository) First(ctx context.Context, conds ...gen.Condition) (*model.PendingUser, error) {
	return r.query.PendingUser.WithContext(ctx).Where(conds...).First()
}

func (r *pendingUserRepository) Create(ctx context.Context, user *model.PendingUser) error {
	return r.query.PendingUser.WithContext(ctx).Create(user)
}

func (r *pendingUserRepository) Updates(ctx context.Context, columns map[string]interface{}, conds ...gen.Condition) (gen.ResultInfo, error) {
	return r.query.PendingUser.WithContext(ctx).Where(conds...).Updates(columns)
}

func (r *pendingUserRepository) Delete(ctx context.Context, conds ...gen.Condition) (gen.ResultInfo, error) {
	return r.query.PendingUser.WithContext(ctx).Where(conds...).Delete()
}

func NewPendingUserRepository(query *query.Query) PendingUserRepository {
	return &pendingUserRepository{query}
}
