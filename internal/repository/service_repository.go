package repository

import (
	"context"
	"net/url"

	"github.com/khanghh/cas-go/model"
	"github.com/khanghh/cas-go/model/query"
	"gorm.io/gen"
)

type ServiceRepository interface {
	WithTx(tx *query.Query) ServiceRepository
	First(ctx context.Context, conds ...gen.Condition) (*model.Service, error)
	GetService(ctx context.Context, serviceUrl string) (*model.Service, error)
}

type mockServiceRepository struct {
}

func (m *mockServiceRepository) First(ctx context.Context, conds ...gen.Condition) (*model.Service, error) {
	return &model.Service{
		ServiceUrl:   "http://localhost:3000",
		AutoLogin:    true,
		CallbackUrl:  "http://localhost:3000/callback",
		ClientId:     "test",
		ClientSecret: "test",
		DisplayName:  "test",
	}, nil
}

func (m *mockServiceRepository) WithTx(tx *query.Query) ServiceRepository {
	return m
}

func (m *mockServiceRepository) GetService(ctx context.Context, serviceUrl string) (*model.Service, error) {
	callbackUrl, _ := url.JoinPath(serviceUrl, "callback")
	return &model.Service{
		ServiceUrl:   serviceUrl,
		AutoLogin:    true,
		CallbackUrl:  callbackUrl,
		ClientId:     "test",
		ClientSecret: "test",
		DisplayName:  "test",
	}, nil
}

func NewMockServiceRepository(query *query.Query) ServiceRepository {
	return &mockServiceRepository{}
}
