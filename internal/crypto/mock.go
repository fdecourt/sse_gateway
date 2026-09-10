//go:build !production

package crypto

import (
	"context"
	"encoding/base64"
	"fmt"
	"sync"
)

// MockUnwrapper simule un KeyUnwrapper en mémoire pour les tests unitaires et benchmarks.
type MockUnwrapper struct {
	mu         sync.RWMutex
	KnownKeys  map[string][]byte // clé = encapsulated_key (ou wrapped_key) -> DEK en clair
	FailNext   bool
	HealthErr  error
	DefaultKey []byte // DEK par défaut retournée si définie (32 octets)
}

// NewMockUnwrapper instancie un déballeur mocké avec une DEK standard si fournie.
func NewMockUnwrapper(defaultDEK []byte) *MockUnwrapper {
	return &MockUnwrapper{
		KnownKeys:  make(map[string][]byte),
		DefaultKey: defaultDEK,
	}
}

// Unwrap retourne la DEK associée ou la clé par défaut.
func (m *MockUnwrapper) Unwrap(ctx context.Context, envelope WrappedKeyEnvelope) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.FailNext {
		return nil, ErrUnwrapFailed
	}

	if dek, ok := m.KnownKeys[envelope.WrappedKey]; ok {
		cpy := make([]byte, len(dek))
		copy(cpy, dek)
		return cpy, nil
	}

	if len(m.DefaultKey) == 32 {
		cpy := make([]byte, 32)
		copy(cpy, m.DefaultKey)
		return cpy, nil
	}

	// Si wrapped_key est un Base64 de 32 octets, on peut le renvoyer directement en mode mock
	decoded, err := base64.StdEncoding.DecodeString(envelope.WrappedKey)
	if err == nil && len(decoded) == 32 {
		return decoded, nil
	}

	return nil, fmt.Errorf("%w: clé enveloppée inconnue du mock", ErrUnwrapFailed)
}

// Health retourne l'état de santé simulé.
func (m *MockUnwrapper) Health(ctx context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.HealthErr
}

// Check adapte la méthode Health pour satisfaire l'interface health.Checker.
func (m *MockUnwrapper) Check(ctx context.Context) error {
	return m.Health(ctx)
}

// Name retourne l'identifiant de la sonde.
func (m *MockUnwrapper) Name() string {
	return "mock_crypto_service"
}

// Close libère les ressources du mock.
func (m *MockUnwrapper) Close() error {
	return nil
}
