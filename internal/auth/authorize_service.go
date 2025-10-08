package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
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

func signHMAC(secret, message string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	signature := mac.Sum(nil)
	return base64.StdEncoding.EncodeToString(signature)
}

func verifyHMAC(secret, message, signatureB64 string) bool {
	expected := signHMAC(secret, message)
	return hmac.Equal([]byte(expected), []byte(signatureB64))
}

func (s *AuthorizeService) ValidateServiceTicket(ctx context.Context, serviceURL string, ticketID string, timestamp string, signature string) (*ServiceTicket, error) {
	ticket, err := s.ticketStore.Get(ctx, ticketID)
	if err != nil {
		return nil, ErrTicketNotFound
	}

	service, err := s.registry.GetServiceByURL(ctx, serviceURL)
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

// removeQueryFromURL parses the service URL and returns the base URL without query
func removeQueryFromURL(urlWithQuery string) (string, error) {
	parsed, err := url.Parse(urlWithQuery)
	if err != nil {
		return "", err
	}
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	return parsed.String(), nil
}

func (s *AuthorizeService) GenerateServiceTicket(ctx context.Context, userId uint, callbackURL string) (*ServiceTicket, error) {
	serviceURL, err := removeQueryFromURL(callbackURL)
	if err != nil {
		return nil, ErrServiceNotFound
	}

	service, err := s.registry.GetServiceByURL(ctx, serviceURL)
	if err != nil {
		return nil, ErrServiceNotFound
	}

	if service.StripQuery {
		callbackURL = service.LoginCallback
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

func NewAuthorizeService(ticketStore store.Store[ServiceTicket], serviceRegistry *ServiceRegistry) *AuthorizeService {
	return &AuthorizeService{
		ticketStore: ticketStore,
		registry:    serviceRegistry,
	}
}
