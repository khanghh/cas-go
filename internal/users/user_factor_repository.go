package users

import (
	"context"

	"github.com/khanghh/cas-go/model"
	"github.com/khanghh/cas-go/model/query"
	"gorm.io/gen"
)

type UserFactorRepository interface {
	WithTx(tx *query.Query) UserFactorRepository
	First(ctx context.Context, conds ...gen.Condition) (*model.UserFactor, error)
	Updates(ctx context.Context, columns map[string]interface{}, conds ...gen.Condition) (gen.ResultInfo, error)
	Delete(ctx context.Context, conds ...gen.Condition) (gen.ResultInfo, error)
}

type userFactorRepository struct {
	query *query.Query
}

func (r *userFactorRepository) WithTx(tx *query.Query) UserFactorRepository {
	return NewUserFactorRepository(tx)
}

func (r *userFactorRepository) First(ctx context.Context, conds ...gen.Condition) (*model.UserFactor, error) {
	return r.query.UserFactor.WithContext(ctx).Where(conds...).First()
}

func (r *userFactorRepository) Create(ctx context.Context, userFactor *model.UserFactor) error {
	return r.query.UserFactor.WithContext(ctx).Create(userFactor)
}

func (r *userFactorRepository) Updates(ctx context.Context, columns map[string]interface{}, conds ...gen.Condition) (gen.ResultInfo, error) {
	return r.query.UserFactor.WithContext(ctx).Where(conds...).Updates(columns)
}

func (r *userFactorRepository) Delete(ctx context.Context, conds ...gen.Condition) (gen.ResultInfo, error) {
	return r.query.UserFactor.WithContext(ctx).Where(conds...).Delete()
}

func NewUserFactorRepository(query *query.Query) UserFactorRepository {
	return &userFactorRepository{query}
}
