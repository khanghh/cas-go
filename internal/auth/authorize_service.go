package auth

import (
	"context"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/repository"
	"github.com/khanghh/cas-go/model"
	"github.com/khanghh/cas-go/model/query"
)

type AuthorizeService struct {
	ticketStorage fiber.Storage
	serviceRepo   repository.ServiceRepository
	tokenRepo     repository.TokenRepository
}

type ServiceTicket struct {
}

func (s *AuthorizeService) GetService(ctx context.Context, serviceUrl string) (*model.Service, error) {
	return s.serviceRepo.First(ctx, query.Service.ServiceUrl.Eq(serviceUrl))
}

func (s *AuthorizeService) AuthorizeUserService(ctx context.Context, user *model.User, serviceUrl string) (string, error) {
	return "", nil
}

func NewAuthorizeService(ticketStorage fiber.Storage, serviceRepo repository.ServiceRepository, tokenRepo repository.TokenRepository) *AuthorizeService {
	return &AuthorizeService{
		ticketStorage: ticketStorage,
		serviceRepo:   serviceRepo,
		tokenRepo:     tokenRepo,
	}
}
