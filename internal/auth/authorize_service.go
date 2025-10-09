package auth

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/khanghh/cas-go/internal/store"
	"github.com/khanghh/cas-go/model"
	"github.com/khanghh/cas-go/model/query"
	"github.com/khanghh/cas-go/params"
	"gorm.io/gen"
)

type ServiceRepository interface {
	WithTx(tx *query.Query) ServiceRepository
	First(ctx context.Context, conds ...gen.Condition) (*model.Service, error)
	Create(ctx context.Context, service *model.Service) error
	Updates(ctx context.Context, columns map[string]interface{}, conds ...gen.Condition) (gen.ResultInfo, error)
	Delete(ctx context.Context, conds ...gen.Condition) error
}

type ServiceTicket struct {
	TicketID    string    `json:"ticketID"    redis:"ticket_id"`
	UserID      uint      `json:"userID"      redis:"user_id"`
	ServiceName string    `json:"serviceName" redis:"service_name"`
	CallbackURL string    `json:"callbackURL" redis:"callback_url"`
	CreateTime  time.Time `json:"createTime"  redis:"create_time"`
}

type registry = ServiceRegistry

type AuthorizeService struct {
	*registry
	ticketStore store.Store[ServiceTicket]
}

func (s *AuthorizeService) ValidateServiceTicket(ctx context.Context, serviceURL string, ticketID string, timestamp string, signature string) (*ServiceTicket, error) {
	ticket, err := s.ticketStore.Get(ctx, ticketID)
	if err != nil {
		return nil, ErrTicketNotFound
	}

	service, err := s.registry.GetService(ctx, serviceURL)
	if err != nil {
		return ticket, ErrServiceNotFound
	}

	message := serviceURL + ticketID + timestamp
	if !verifyHMAC(service.SigningKey, message, signature) {
		return ticket, ErrInvalidSignature
	}

	// Attempt to remove the ticket. If it doesn't exist, it has either expired or been used.
	if err := s.ticketStore.Delete(ctx, ticketID); err != nil {
		return ticket, ErrTicketExpired
	}

	return ticket, nil
}

func (s *AuthorizeService) GenerateServiceTicket(ctx context.Context, userId uint, callbackURL string) (*ServiceTicket, error) {
	service, err := s.registry.GetService(ctx, callbackURL)
	if err != nil {
		return nil, ErrServiceNotFound
	}

	if service.StripQuery {
		callbackURL = service.LoginURL
	}

	st := ServiceTicket{
		TicketID:    uuid.NewString(),
		UserID:      userId,
		CallbackURL: callbackURL,
		CreateTime:  time.Now(),
	}

	err = s.ticketStore.Set(ctx, st.TicketID, st, params.ServiceTicketExpiration)
	if err != nil {
		return nil, err
	}

	return &st, nil
}

func NewAuthorizeService(ticketStore store.Store[ServiceTicket], serviceRepo ServiceRepository) *AuthorizeService {
	return &AuthorizeService{
		ticketStore: ticketStore,
		registry:    NewServiceRegistry(serviceRepo),
	}
}
