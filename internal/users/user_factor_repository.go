package users

import (
	"context"

	"github.com/khanghh/cas-go/model"
	"github.com/khanghh/cas-go/model/query"
	"gorm.io/gen"
	"gorm.io/gorm/clause"
)

type AuthFactor string

const (
	AuthFactorEmail AuthFactor = "email"
	AuthFactorTOTP  AuthFactor = "totp"
)

type UserFactorRepository interface {
	WithTx(tx *query.Query) UserFactorRepository
	Create(ctx context.Context, user *model.UserFactor) error
	First(ctx context.Context, conds ...gen.Condition) (*model.UserFactor, error)
	Find(ctx context.Context, conds ...gen.Condition) ([]*model.UserFactor, error)
	Delete(ctx context.Context, conds ...gen.Condition) (gen.ResultInfo, error)
	Upsert(ctx context.Context, userFactor *model.UserFactor) error
	Updates(ctx context.Context, columns map[string]interface{}, conds ...gen.Condition) (gen.ResultInfo, error)
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

func (r *userFactorRepository) Find(ctx context.Context, conds ...gen.Condition) ([]*model.UserFactor, error) {
	return r.query.UserFactor.WithContext(ctx).Where(conds...).Find()
}

func (r *userFactorRepository) Delete(ctx context.Context, conds ...gen.Condition) (gen.ResultInfo, error) {
	return r.query.UserFactor.WithContext(ctx).Where(conds...).Delete()
}

func (r *userFactorRepository) Upsert(ctx context.Context, userFactor *model.UserFactor) error {
	return r.query.UserFactor.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: query.ColUserFactorUserID}, {Name: query.ColUserFactorType}},          // conflict target
			DoUpdates: clause.AssignmentColumns([]string{query.ColUserFactorEnabled, query.ColUserFactorUpdatedAt}), // only these fields updated
		}).
		Returning(&userFactor).
		Create(userFactor)
}

func (r *userFactorRepository) Updates(ctx context.Context, columns map[string]interface{}, conds ...gen.Condition) (gen.ResultInfo, error) {
	return r.query.UserFactor.WithContext(ctx).Where(conds...).Updates(columns)
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
