package auth

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
)

type TicketStore struct {
	storage fiber.Storage
}

func (s *TicketStore) GetTicket(ticketID string) (*ServiceTicket, error) {
	blob, err := s.storage.Get(ticketID)
	if err != nil {
		return nil, err
	}
	fmt.Printf("blob: %s", blob)
	var ticket ServiceTicket
	if err := json.Unmarshal(blob, &ticket); err != nil {
		return nil, err
	}
	return &ticket, nil
}

func (s *TicketStore) CreateTicket(ticket *ServiceTicket, expireDuration time.Duration) error {
	blob, _ := json.Marshal(ticket)
	return s.storage.Set(ticket.TicketID, blob, expireDuration)
}

func (s *TicketStore) RemoveTicket(ticketID string) error {
	return s.storage.Delete(ticketID)
}

func NewTicketStore(storage fiber.Storage) *TicketStore {
	return &TicketStore{
		storage: storage,
	}
}
