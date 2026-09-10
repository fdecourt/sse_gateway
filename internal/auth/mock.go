//go:build !production

package auth

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// MockValidator implémente TicketValidator pour faciliter les tests unitaires et benchmarks sans cryptographie lourde.
type MockValidator struct {
	mu           sync.RWMutex
	ValidTickets map[string]*Capability
	DefaultCap   *Capability
	FailNext     bool
	HealthErr    error
}

// NewMockValidator crée un validateur en mémoire.
func NewMockValidator() *MockValidator {
	return &MockValidator{
		ValidTickets: make(map[string]*Capability),
		DefaultCap: &Capability{
			UserID:    "user-test-1",
			TenantID:  "tenant-default",
			AppID:     "app-default",
			Topics:    []string{"topic-1", "topic-2"},
			Audience:  "sse-gateway",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		},
	}
}

// Validate retourne la capability enregistrée ou par défaut.
func (m *MockValidator) Validate(ctx context.Context, rawTicket string) (*Capability, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.FailNext {
		return nil, ErrInvalidTicket
	}

	if capability, ok := m.ValidTickets[rawTicket]; ok {
		if !capability.ExpiresAt.IsZero() && time.Now().After(capability.ExpiresAt) {
			return nil, ErrExpiredTicket
		}
		return capability, nil
	}

	if m.DefaultCap != nil {
		return m.DefaultCap, nil
	}

	return nil, fmt.Errorf("%w: ticket non reconnu par le mock", ErrInvalidTicket)
}

// Health retourne l'état de santé simulé.
func (m *MockValidator) Health(ctx context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.HealthErr
}
