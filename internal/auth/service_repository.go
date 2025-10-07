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

func (r *serviceRepository) WithTx(tx *query.Query) ServiceRepository {
	return NewServiceRepository(tx)
}

func (r *serviceRepository) First(ctx context.Context, conds ...gen.Condition) (*model.Service, error) {
	return r.query.Service.WithContext(ctx).Where(conds...).First()
}

func (r *serviceRepository) Create(ctx context.Context, service *model.Service) error {
	return r.query.Service.WithContext(ctx).Create(service)
}

func (r *serviceRepository) Updates(ctx context.Context, columns map[string]interface{}, conds ...gen.Condition) (gen.ResultInfo, error) {
	return r.query.Service.WithContext(ctx).Where(conds...).Updates(columns)
}

func NewServiceRepository(query *query.Query) ServiceRepository {
	return &serviceRepository{
		query: query,
	}
}
