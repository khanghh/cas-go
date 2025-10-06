package auth

import (
	"context"

	"github.com/khanghh/cas-go/model"
	"github.com/khanghh/cas-go/model/query"
	"gorm.io/gen"
)

type serviceRepository struct {
	query *query.Query
}

func (r *serviceRepository) First(ctx context.Context, conds ...gen.Condition) (*model.Service, error) {
	return r.query.Service.WithContext(ctx).Where(conds...).First()
}

func (r *serviceRepository) WithTx(tx *query.Query) ServiceRepository {
	return NewServiceRepository(tx)
}

func (r *serviceRepository) GetService(ctx context.Context, svcCallbackURL string) (*model.Service, error) {
	return r.query.Service.WithContext(ctx).Where(query.Service.CallbackURL.Eq(svcCallbackURL)).First()
}

func (r *serviceRepository) AddService(ctx context.Context, service *model.Service) error {
	return r.query.Service.Create(service)
}

func NewServiceRepository(query *query.Query) ServiceRepository {
	return &serviceRepository{
		query: query,
	}
}
