package repository

import (
	"context"

	"github.com/khanghh/cas-go/model"
	"github.com/khanghh/cas-go/model/query"
	"gorm.io/gen"
	"gorm.io/gen/field"
	"gorm.io/gorm/clause"
)

type UserOAuthRepository interface {
	WithTx(tx *query.Query) UserOAuthRepository
	First(ctx context.Context, conds ...gen.Condition) (*model.UserOAuth, error)
	Upsert(ctx context.Context, userOAuth *model.UserOAuth) error
	Find(ctx context.Context, conds ...gen.Condition) ([]*model.UserOAuth, error)
	CreateIfNotExists(ctx context.Context, userOAuth *model.UserOAuth) (*model.UserOAuth, error)
}

type userOAuthRepository struct {
	query *query.Query
}

func (r *userOAuthRepository) First(ctx context.Context, conds ...gen.Condition) (*model.UserOAuth, error) {
	return r.query.UserOAuth.WithContext(ctx).Where(conds...).First()
}

func (r *userOAuthRepository) WithTx(tx *query.Query) UserOAuthRepository {
	return NewUserOAuthRepository(tx)
}

func (r *userOAuthRepository) Upsert(ctx context.Context, userOAuth *model.UserOAuth) error {
	return r.query.UserOAuth.WithContext(ctx).
		Clauses(clause.OnConflict{DoNothing: true}).
		Returning(&userOAuth).
		Create(userOAuth)
}

func (r *userOAuthRepository) CreateIfNotExists(ctx context.Context, userOAuth *model.UserOAuth) (*model.UserOAuth, error) {
	return r.query.UserOAuth.WithContext(ctx).
		Where(
			query.UserOAuth.Provider.Eq(userOAuth.Provider),
			query.UserOAuth.ProfileID.Eq(userOAuth.ProfileID),
		).
		Attrs(field.Attrs(userOAuth)).
		FirstOrCreate()
}

func (r *userOAuthRepository) Find(ctx context.Context, conds ...gen.Condition) ([]*model.UserOAuth, error) {
	return r.query.UserOAuth.WithContext(ctx).Where(conds...).Find()
}

func NewUserOAuthRepository(query *query.Query) UserOAuthRepository {
	return &userOAuthRepository{query}
}
