package bus

import (
	"context"
	"errors"
	"time"

	"sse-gateway/internal/crypto"
)

var (
	// ErrBusClosed signale que le bus d'événements a été fermé.
	ErrBusClosed = errors.New("le bus d'événements est fermé")
	// ErrBusUnavailable signale l'indisponibilité du bus d'événements.
	ErrBusUnavailable = errors.New("le bus d'événements est inaccessible")
)

// SupportedEventSchema identifie la version de schéma supportée pour les événements entrants.
const SupportedEventSchema = "realtime-event-v1"

// EncryptedPayload regroupe les composants cryptographiques nécessaires au déballage et déchiffrement local.
//
// Deux nonces distincts coexistent et ne doivent jamais être confondus :
//   - Nonce        : nonce AES-GCM de l'enveloppe, protégeant WrappedKey. Transmis au service
//     de déballage (PQC gateway) qui s'en sert pour ouvrir la DEK.
//   - PayloadNonce : nonce AES-GCM du Ciphertext, utilisé localement une fois la DEK obtenue.
//
// Ce sont deux opérations de chiffrement sous deux clés différentes : réutiliser la même valeur
// contraindrait le producteur et masquerait une erreur de protocole.
type EncryptedPayload struct {
	Algorithm       string `json:"algorithm,omitempty"`
	Version         string `json:"version,omitempty"`
	SuiteID         uint16 `json:"suite_id,omitempty"`
	EncapsulatedKey string `json:"encapsulated_key,omitempty"`
	WrappedKey      string `json:"wrapped_key,omitempty"`
	Nonce           string `json:"nonce,omitempty"`
	PayloadNonce    string `json:"payload_nonce,omitempty"`
	Ciphertext      string `json:"ciphertext,omitempty"`
}

// EncryptedEvent modélise le format générique de tout événement reçu depuis l'EventBus (schema realtime-event-v1).
type EncryptedEvent struct {
	Schema       string           `json:"schema,omitempty"`
	EventID      string           `json:"event_id,omitempty"`
	TenantID     string           `json:"tenant_id"`
	AppID        string           `json:"app_id,omitempty"`
	TopicID      string           `json:"topic_id,omitempty"`
	Type         string           `json:"type"`
	EntityID     string           `json:"entity_id,omitempty"`
	Version      int64            `json:"version,omitempty"`
	OriginUserID string           `json:"origin_user_id,omitempty"`
	UserID       string           `json:"user_id,omitempty"` // Utilisé notamment pour auth.invalidate
	CreatedAt    time.Time        `json:"created_at,omitempty"`
	Crypto       EncryptedPayload `json:"crypto,omitempty"`

	// RawChannel contient le nom du canal / topic source physique sur lequel l'événement a transité
	RawChannel string `json:"-"`

	// RoutingKey porte la clé de routage calculée en amont afin d'éviter tout recalcul sur le chemin chaud
	RoutingKey string `json:"-"`
}

// IsSchemaSupported vérifie que le schéma de l'événement est compatible avec la passerelle s'il est spécifié.
func (e *EncryptedEvent) IsSchemaSupported() bool {
	return e.Schema == "" || e.Schema == SupportedEventSchema
}

// ToEnvelope convertit le payload en WrappedKeyEnvelope pour le KeyUnwrapper.
func (e *EncryptedEvent) ToEnvelope() crypto.WrappedKeyEnvelope {
	return crypto.WrappedKeyEnvelope{
		Algorithm:       e.Crypto.Algorithm,
		Version:         e.Crypto.Version,
		SuiteID:         e.Crypto.SuiteID,
		EncapsulatedKey: e.Crypto.EncapsulatedKey,
		Nonce:           e.Crypto.Nonce,
		WrappedKey:      e.Crypto.WrappedKey,
	}
}

// Bus abstrait le fournisseur physique de transport d'événements (Valkey, NATS, Redis, In-Memory).
type Bus interface {
	// Subscribe écoute un ensemble de patterns ou channels et retourne un flux unifié de messages chiffrés.
	Subscribe(ctx context.Context, patterns []string) (<-chan EncryptedEvent, error)

	// Health valide la connectivité avec le bus d'événements.
	Health(ctx context.Context) error

	// Close arrête proprement les souscriptions et libère les connexions.
	Close() error
}
