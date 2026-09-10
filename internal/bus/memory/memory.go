package memory

import (
	"context"
	"sync"

	"sse-gateway/internal/bus"
)

// Bus implémente un EventBus en mémoire ultra-rapide pour tests, benchmarks ou mode autonome.
type Bus struct {
	mu          sync.RWMutex
	subscribers []chan bus.EncryptedEvent
	closed      bool
	bufferSize  int
}

// NewBus instancie le bus en mémoire avec une taille de buffer de canal configurable.
func NewBus(bufferSize int) *Bus {
	if bufferSize <= 0 {
		bufferSize = 1024
	}
	return &Bus{
		bufferSize: bufferSize,
	}
}

// Subscribe s'abonne au bus et renvoie un canal d'événements chiffrés.
func (b *Bus) Subscribe(ctx context.Context, _ []string) (<-chan bus.EncryptedEvent, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil, bus.ErrBusClosed
	}

	ch := make(chan bus.EncryptedEvent, b.bufferSize)
	b.subscribers = append(b.subscribers, ch)

	go func() {
		<-ctx.Done()
		b.mu.Lock()
		defer b.mu.Unlock()
		for i, sub := range b.subscribers {
			if sub == ch {
				b.subscribers = append(b.subscribers[:i], b.subscribers[i+1:]...)
				close(ch)
				break
			}
		}
	}()

	return ch, nil
}

// Publish diffuse un événement chiffré vers tous les abonnés en mémoire.
func (b *Bus) Publish(event bus.EncryptedEvent) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return
	}

	for _, sub := range b.subscribers {
		select {
		case sub <- event:
		default:
			// Si le buffer d'un abonné est plein, on ne bloque pas les autres abonnés
		}
	}
}

// Health retourne l'état de santé du bus.
func (b *Bus) Health(_ context.Context) error {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed {
		return bus.ErrBusClosed
	}
	return nil
}

// Check adapte la méthode Health pour satisfaire l'interface health.Checker.
func (b *Bus) Check(ctx context.Context) error {
	return b.Health(ctx)
}

// Name retourne l'identifiant de la sonde.
func (b *Bus) Name() string {
	return "memory_event_bus"
}

// Close ferme le bus et l'ensemble des canaux d'abonnés actifs.
func (b *Bus) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}
	b.closed = true

	for _, sub := range b.subscribers {
		close(sub)
	}
	b.subscribers = nil
	return nil
}
