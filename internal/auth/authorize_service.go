package auth

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/internal/repository"
	"github.com/khanghh/cas-go/model"
)

type AuthorizeService struct {
	ticketStorage fiber.Storage
	serviceRepo   repository.ServiceRepository
	tokenRepo     repository.TokenRepository
}

type ServiceTicket struct {
	TicketId   string
	ServiceUrl string
	ExpireTime time.Time
}

func (s *AuthorizeService) ValidateServiceTicket(ctx context.Context, serviceTicket string, timestamp string, signature string) (bool, error) {
	return false, nil
}

func (s *AuthorizeService) GenerateServiceTicket(ctx context.Context, user *model.User, service *model.Service) (*ServiceTicket, error) {
	return nil, nil
}

func NewAuthorizeService(ticketStorage fiber.Storage, serviceRepo repository.ServiceRepository, tokenRepo repository.TokenRepository) *AuthorizeService {
	return &AuthorizeService{
		ticketStorage: ticketStorage,
		serviceRepo:   serviceRepo,
		tokenRepo:     tokenRepo,
	}
}
