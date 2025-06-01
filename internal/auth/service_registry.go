package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"

	"github.com/khanghh/cas-go/internal/repository"
	"github.com/khanghh/cas-go/model"
	"github.com/khanghh/cas-go/model/query"
)

type ServiceRegistry struct {
	serviceRepo repository.ServiceRepository
}

func generateEd25519KeyPair(rand io.Reader) (string, string, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(privKey), base64.StdEncoding.EncodeToString(pubKey), nil
}

func (r *ServiceRegistry) RegisterService(ctx context.Context, service *model.Service) (string, error) {
	privKey, pubKey, err := generateEd25519KeyPair(rand.Reader)
	if err != nil {
		return "", err
	}

	service.PublicKey = pubKey
	if err := r.serviceRepo.AddService(ctx, service); err != nil {
		return "", err
	}

	return privKey, nil
}

func (r *ServiceRegistry) GetService(ctx context.Context, serviceUrl string) (*model.Service, error) {
	return r.serviceRepo.First(ctx, query.Service.ServiceUrl.Eq(serviceUrl))
}

func NewServiceRegistry(serviceRepo repository.ServiceRepository) *ServiceRegistry {
	return &ServiceRegistry{
		serviceRepo: serviceRepo,
	}
}
