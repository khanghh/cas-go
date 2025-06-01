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
	TicketId    string    `json:"ticketId"`
	UserId      uint      `json:"userId"`
	Service     string    `json:"serviceUrl"`
	CallbackUrl string    `json:"callbackUrl"`
	CreateTime  time.Time `json:"createTime"`
}

type AuthorizeService struct {
	ticketStore *TicketStore
	serviceRepo repository.ServiceRepository
	tokenRepo   repository.TokenRepository
}

func mustDecodeBase64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return []byte{}
	}
	return b
}

func (s *AuthorizeService) validateTicketSignature(publicKey, signature, serviceURL, ticketId, timestamp string) bool {
	sig := mustDecodeBase64(signature)
	if len(sig) != ed25519.SignatureSize {
		return false
	}

	pubKey := mustDecodeBase64(publicKey)
	if len(pubKey) != ed25519.PublicKeySize {
		return false
	}

	data := serviceURL + ticketId + timestamp
	hash := sha256.Sum256([]byte(data))
	message := hex.EncodeToString(hash[:])
	return ed25519.Verify(pubKey, []byte(message), sig)
}

func (s *AuthorizeService) ValidateServiceTicket(ctx context.Context, serviceUrl string, ticketId string, timestamp string, signature string) (bool, error) {
	ticket, err := s.ticketStore.GetTicket(ticketId)
	if err != nil {
		return false, ErrTicketNotFound
	}

	if ticket.Service != serviceUrl {
		return false, ErrServiceUrlMismatch
	}

	service, err := s.serviceRepo.GetService(ctx, serviceUrl)
	if err != nil {
		return false, ErrServiceNotFound
	}

	if s.validateTicketSignature(service.PublicKey, signature, serviceUrl, ticketId, timestamp) {
		if err := s.ticketStore.RemoveTicket(ticketId); err != nil {
			return false, ErrTicketExpired
		}
		return true, nil
	}

	return false, nil
}

func (s *AuthorizeService) GenerateServiceTicket(ctx context.Context, userId uint, serviceUrl string) (*ServiceTicket, error) {
	service, err := s.serviceRepo.GetService(ctx, serviceUrl)
	if err != nil {
		return nil, ErrServiceNotFound
	}

	st := &ServiceTicket{
		TicketId:    uuid.NewString(),
		UserId:      userId,
		Service:     serviceUrl,
		CallbackUrl: service.CallbackUrl,
		CreateTime:  time.Now(),
	}

	if err := s.ticketStore.CreateTicket(st, params.SerivceTicketExpireDuration); err != nil {
		return nil, err
	}

	return st, nil
}

func NewAuthorizeService(ticketStore *TicketStore, serviceRepo repository.ServiceRepository, tokenRepo repository.TokenRepository) *AuthorizeService {
	return &AuthorizeService{
		ticketStore: ticketStore,
		serviceRepo: serviceRepo,
		tokenRepo:   tokenRepo,
	}
}
