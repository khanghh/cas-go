package auth

import (
	"context"

	"github.com/khanghh/cas-go/internal/repository"
	"github.com/khanghh/cas-go/model"
)

type ServiceRegistry struct {
	serviceRepo repository.ServiceRepository
}

func (r *ServiceRegistry) RegisterService(ctx context.Context, service *model.Service) error {
	r.serviceRepo.AddService(ctx, service)
	return nil
}

func (r *ServiceRegistry) GetService(ctx context.Context, serviceUrl string) (*model.Service, error) {
	return nil, nil
}

func NewServiceRegistry(serviceRepo repository.ServiceRepository) *ServiceRegistry {
	return &ServiceRegistry{
		serviceRepo: serviceRepo,
	}
}
