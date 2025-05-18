package repository

import (
	"context"

	"github.com/khanghh/cas-go/model"
	"github.com/khanghh/cas-go/model/query"
	"gorm.io/gen"
	"gorm.io/gorm/clause"
)

type OAuthRepository interface {
	WithTx(tx *query.Query) OAuthRepository
	First(ctx context.Context, conds ...gen.Condition) (*model.UserOAuth, error)
	Upsert(ctx context.Context, userOAuth *model.UserOAuth) error
}

type oauthRepository struct {
	query *query.Query
}

func (r *oauthRepository) First(ctx context.Context, conds ...gen.Condition) (*model.UserOAuth, error) {
	panic("TODO: Implement")
}

func (r *oauthRepository) WithTx(tx *query.Query) OAuthRepository {
	panic("TODO: Implement")
}

func (r *oauthRepository) Upsert(ctx context.Context, userOAuth *model.UserOAuth) error {
	return r.query.UserOAuth.WithContext(ctx).
		Clauses(clause.OnConflict{UpdateAll: true}).
		Returning(userOAuth).
		Create(userOAuth)
}

func NewOAuthRepository(query *query.Query) OAuthRepository {
	return &oauthRepository{query}
}
