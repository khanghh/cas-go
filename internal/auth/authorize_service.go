package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
	"github.com/khanghh/cas-go/internal/repository"
	"github.com/khanghh/cas-go/params"
)

type ServiceTicket struct {
	TicketID    string    `json:"ticketID"`
	UserID      uint      `json:"userID"`
	CallbackURL string    `json:"callbackURL"`
	CreateTime  time.Time `json:"createTime"`
}

type registry = ServiceRegistry

type AuthorizeService struct {
	*registry
	ticketStore *TicketStore
	tokenRepo   repository.TokenRepository
}

func mustDecodeBase64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return []byte{}
	}
	return b
}

func (s *AuthorizeService) validateTicketSignature(publicKey, signature, serviceURL, ticketID, timestamp string) bool {
	sig := mustDecodeBase64(signature)
	if len(sig) != ed25519.SignatureSize {
		return false
	}

	pubKey := mustDecodeBase64(publicKey)
	if len(pubKey) != ed25519.PublicKeySize {
		return false
	}

	data := serviceURL + ticketID + timestamp
	hash := sha256.Sum256([]byte(data))
	message := hex.EncodeToString(hash[:])
	return ed25519.Verify(pubKey, []byte(message), sig)
}

func (s *AuthorizeService) ValidateServiceTicket(ctx context.Context, serviceURL string, ticketId string, timestamp string, signature string) (bool, error) {
	ticket, err := s.ticketStore.GetTicket(ticketId)
	if err != nil {
		return false, ErrTicketNotFound
	}

	if ticket.CallbackURL != serviceURL {
		return false, ErrServiceUrlMismatch
	}

	service, err := s.registry.GetService(ctx, serviceURL)
	if err != nil {
		return false, ErrServiceNotFound
	}

	if s.validateTicketSignature(service.PublicKey, signature, serviceURL, ticketId, timestamp) {
		if err := s.ticketStore.RemoveTicket(ticketId); err != nil {
			return false, ErrTicketExpired
		}
		return true, nil
	}

	return false, nil
}

func (s *AuthorizeService) GenerateServiceTicket(ctx context.Context, userId uint, svcCallbackURL string) (*ServiceTicket, error) {
	service, err := s.registry.GetService(ctx, svcCallbackURL)
	if err != nil {
		return nil, ErrServiceNotFound
	}

	st := &ServiceTicket{
		TicketID:    uuid.NewString(),
		UserID:      userId,
		CallbackURL: service.CallbackURL,
		CreateTime:  time.Now(),
	}

	if err := s.ticketStore.CreateTicket(st, params.ServiceTicketExpiration); err != nil {
		return nil, err
	}

	return st, nil
}

func NewAuthorizeService(ticketStore *TicketStore, serviceRegistry *ServiceRegistry, tokenRepo repository.TokenRepository) *AuthorizeService {
	return &AuthorizeService{
		ticketStore: ticketStore,
		registry:    serviceRegistry,
		tokenRepo:   tokenRepo,
	}
}
