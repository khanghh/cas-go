package repository

import (
	"context"

	"github.com/khanghh/cas-go/model"
	"github.com/khanghh/cas-go/model/query"
	"gorm.io/gen"
)

type ServiceRepository interface {
	WithTx(tx *query.Query) ServiceRepository
	First(ctx context.Context, conds ...gen.Condition) (*model.Service, error)
	GetService(ctx context.Context, serviceUrl string) (*model.Service, error)
	AddService(ctx context.Context, service *model.Service) error
}

type serviceRepository struct {
	query *query.Query
}

func (r *serviceRepository) First(ctx context.Context, conds ...gen.Condition) (*model.Service, error) {
	return r.query.Service.WithContext(ctx).Where(conds...).First()
}

func (r *serviceRepository) WithTx(tx *query.Query) ServiceRepository {
	return NewServiceRepository(tx)
}

func (r *serviceRepository) GetService(ctx context.Context, serviceUrl string) (*model.Service, error) {
	return r.query.Service.WithContext(ctx).Where(query.Service.ServiceUrl.Eq(serviceUrl)).First()
}

func (r *serviceRepository) AddService(ctx context.Context, service *model.Service) error {
	return r.query.Service.Create(service)
}

func NewServiceRepository(query *query.Query) ServiceRepository {
	return &serviceRepository{
		query: query,
	}
}
