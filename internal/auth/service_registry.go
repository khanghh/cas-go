package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"

	"github.com/khanghh/cas-go/model"
	"github.com/khanghh/cas-go/model/query"
	"gorm.io/gorm"
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
	if err := r.serviceRepo.Create(ctx, service); err != nil {
		return "", err
	}

	return signingKey, nil
}

func (r *ServiceRegistry) GetService(ctx context.Context, serviceName string) (*model.Service, error) {
	svc, err := r.serviceRepo.First(ctx, query.Service.Name.Eq(serviceName))
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrServiceNotFound
	}
	return svc, err
}

func (r *ServiceRegistry) GetServiceByURL(ctx context.Context, loginURL string) (*model.Service, error) {
	loginURL = removeQueryFromURL(loginURL)
	if loginURL == "" {
		return nil, ErrServiceNotFound
	}
	svc, err := r.serviceRepo.First(ctx, query.Service.LoginURL.Eq(loginURL))
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrServiceNotFound
	}
	return svc, err
}

func NewServiceRegistry(serviceRepo ServiceRepository) *ServiceRegistry {
	return &ServiceRegistry{
		serviceRepo: serviceRepo,
	}
}
