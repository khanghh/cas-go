package repository

import (
	"context"

	"github.com/khanghh/cas-go/model"
	"github.com/khanghh/cas-go/model/query"
	"gorm.io/gen"
)

type TokenRepository interface {
	WithTx(tx *query.Query) TokenRepository
	First(ctx context.Context, conds ...gen.Condition) (*model.Token, error)
}

type tokenRepository struct {
	query *query.Query
}

func (t *tokenRepository) First(ctx context.Context, conds ...gen.Condition) (*model.Token, error) {
	panic("TODO: Implement")
}

func (t *tokenRepository) WithTx(tx *query.Query) TokenRepository {
	panic("TODO: Implement")
}

func NewTokenRepository(query *query.Query) TokenRepository {
	return &tokenRepository{query}
}
