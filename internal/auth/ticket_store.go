package auth

import (
	"encoding/json"

	"github.com/gofiber/fiber/v2"
	"github.com/khanghh/cas-go/params"
)

type TicketStore struct {
	storage fiber.Storage
}

func (s *TicketStore) GetTicket(ticketId string) (*ServiceTicket, error) {
	blob, err := s.storage.Get(ticketId)
	if err != nil {
		return nil, err
	}
	var ticket ServiceTicket
	if err := json.Unmarshal(blob, &ticket); err != nil {
		return nil, err
	}
	return &ticket, nil
}

func (s *TicketStore) AddTicket(ticket *ServiceTicket) error {
	blob, _ := json.Marshal(ticket)
	return s.storage.Set(ticket.TicketId, blob, params.SerivceTicketExpireDuration)
}

func (s *TicketStore) RemoveTicket(ticketId string) error {
	return s.storage.Delete(ticketId)
}

func NewTicketStore(storage fiber.Storage) *TicketStore {
	return &TicketStore{
		storage: storage,
	}
}
