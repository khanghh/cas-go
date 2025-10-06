package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"

	"github.com/khanghh/cas-go/model"
	"github.com/khanghh/cas-go/model/query"
)

type ServiceRegistry struct {
	serviceRepo ServiceRepository
}

func generateHMACKey(size int) (string, error) {
	key := make([]byte, size)
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

func (r *ServiceRegistry) RegisterService(ctx context.Context, service *model.Service) (string, error) {
	signingKey, err := generateHMACKey(32)
	if err != nil {
		return "", err
	}

	service.SigningKey = signingKey
	if err := r.serviceRepo.AddService(ctx, service); err != nil {
		return "", err
	}

	return signingKey, nil
}

func (r *ServiceRegistry) GetService(ctx context.Context, svcCallbackURL string) (*model.Service, error) {
	return r.serviceRepo.First(ctx, query.Service.CallbackURL.Eq(svcCallbackURL))
}

func NewServiceRegistry(serviceRepo ServiceRepository) *ServiceRegistry {
	return &ServiceRegistry{
		serviceRepo: serviceRepo,
	}
}
