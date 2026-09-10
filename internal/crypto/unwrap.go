package crypto

import (
	"context"
	"errors"
)

var (
	// ErrUnwrapFailed signale un échec de déballage de la clé DEK par le service cryptographique.
	ErrUnwrapFailed = errors.New("échec du déballage de la clé (Key Unwrap)")
	// ErrInvalidEnvelope signale des métadonnées ou des clés encapsulées malformées ou incomplètes.
	ErrInvalidEnvelope = errors.New("enveloppe cryptographique invalide ou incomplète")
	// ErrCryptoServiceUnavailable signale l'inaccessibilité du service cryptographique distant.
	ErrCryptoServiceUnavailable = errors.New("service cryptographique distant indisponible")
)

// WrappedKeyEnvelope contient les métadonnées et composants nécessaires au déballage d'une clé DEK.
type WrappedKeyEnvelope struct {
	Algorithm string `json:"algorithm,omitempty"`
	Version   string `json:"version,omitempty"`
	// SuiteID identifie la suite cryptographique. Le service de déballage l'attend
	// sous forme d'entier non signé 16 bits, jamais de chaîne.
	SuiteID         uint16 `json:"suite_id,omitempty"`
	EncapsulatedKey string `json:"encapsulated_key"`
	// Nonce est le nonce AES-GCM de l'enveloppe (celui qui protège WrappedKey),
	// à ne pas confondre avec le nonce du payload applicatif.
	Nonce      string `json:"nonce,omitempty"`
	WrappedKey string `json:"wrapped_key"`
}

// KeyUnwrapper isole l'implémentation concrète de déballage de clés (HTTP, IPC, KMS, etc.).
type KeyUnwrapper interface {
	// Unwrap déchiffre/décapsule l'enveloppe et retourne la clé symétrique DEK en clair (32 octets).
	// L'appelant DOIT s'assurer de nettoyer la DEK via crypto.Zeroize(dek) dès son utilisation terminée.
	Unwrap(ctx context.Context, envelope WrappedKeyEnvelope) ([]byte, error)

	// Health vérifie la disponibilité opérationnelle du fournisseur de déballage de clés.
	Health(ctx context.Context) error

	// Close libère les ressources associées au provider.
	Close() error
}
