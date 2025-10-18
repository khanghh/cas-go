package users

import (
	"context"

	"github.com/khanghh/cas-go/model"
	"github.com/khanghh/cas-go/model/query"
	"gorm.io/gen"
	"gorm.io/gorm/clause"
)

type UserFactorRepository interface {
	WithTx(tx *query.Query) UserFactorRepository
	Create(ctx context.Context, user *model.UserFactor) error
	First(ctx context.Context, conds ...gen.Condition) (*model.UserFactor, error)
	Delete(ctx context.Context, conds ...gen.Condition) (gen.ResultInfo, error)
	Upsert(ctx context.Context, userFactor *model.UserFactor) error
	GetUserFactor(ctx context.Context, uid uint, factorType string) (*model.UserFactor, error)
}

type userFactorRepository struct {
	query *query.Query
}

func (r *userFactorRepository) WithTx(tx *query.Query) UserFactorRepository {
	return NewUserFactorRepository(tx)
}

func (r *userFactorRepository) Create(ctx context.Context, userFactor *model.UserFactor) error {
	return r.query.UserFactor.WithContext(ctx).Create(userFactor)
}

func (r *userFactorRepository) First(ctx context.Context, conds ...gen.Condition) (*model.UserFactor, error) {
	return r.query.UserFactor.WithContext(ctx).Where(conds...).First()
}

func (r *userFactorRepository) Delete(ctx context.Context, conds ...gen.Condition) (gen.ResultInfo, error) {
	return r.query.UserFactor.WithContext(ctx).Where(conds...).Delete()
}

func (r *userFactorRepository) Upsert(ctx context.Context, userFactor *model.UserFactor) error {
	return r.query.UserFactor.WithContext(ctx).
		Clauses(clause.OnConflict{UpdateAll: true}).
		Returning(&userFactor).
		Create(userFactor)
}

func (r *userFactorRepository) GetUserFactor(ctx context.Context, uid uint, factorType string) (*model.UserFactor, error) {
	return r.query.UserFactor.WithContext(ctx).Where(
		query.UserFactor.UserID.Eq(uid),
		query.UserFactor.Type.Eq(factorType),
	).First()
}

func NewUserFactorRepository(query *query.Query) UserFactorRepository {
	return &userFactorRepository{query}
}
