package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var (
	// ErrInvalidKeySize est levé lorsque la clé DEK fournie ne fait pas 32 octets (AES-256).
	ErrInvalidKeySize = errors.New("taille de clé DEK invalide pour AES-256 (32 octets requis)")
	// ErrDecryptFailed est levé lorsque le déchiffrement AES-GCM échoue (mauvaise clé, ciphertext altéré ou AAD non concordant).
	ErrDecryptFailed = errors.New("échec d'authentification ou déchiffrement du ciphertext AES-GCM")
	// ErrPayloadTooLarge signale un dépassement de la limite configurée pour le payload déchiffré.
	ErrPayloadTooLarge = errors.New("taille du payload déchiffré supérieure à la limite maximale autorisée")
	// ErrMissingPayloadNonce signale un événement dépourvu du nonce AES-GCM propre au payload
	// (champ crypto.payload_nonce), distinct du nonce d'enveloppe.
	ErrMissingPayloadNonce = errors.New("nonce du payload absent de l'événement (champ crypto.payload_nonce requis)")
)

// DefaultAADTemplate est le gabarit d'AAD appliqué en l'absence de configuration
// explicite. Il lie le chiffré à son contexte de routage : un même ciphertext
// rejoué sous un autre tenant, une autre application ou une autre version échoue
// à l'authentification GCM. Producteurs et consommateurs doivent partager cette
// valeur, d'où sa déclaration unique ici plutôt qu'un littéral par appelant.
const DefaultAADTemplate = "{tenant_id}|{app_id}|{topic_id}|{event_id}|{version}"

// AADContext contient les métadonnées de routage permettant de construire les données additionnelles authentifiées (AAD).
type AADContext struct {
	TenantID string
	AppID    string
	TopicID  string
	EventID  string
	Version  int64
}

// BuildAAD formate les données additionnelles authentifiées à partir du gabarit configurable.
func BuildAAD(template string, ctx AADContext) []byte {
	if template == "" {
		return nil
	}
	r := strings.NewReplacer(
		"{tenant_id}", ctx.TenantID,
		"{app_id}", ctx.AppID,
		"{topic_id}", ctx.TopicID,
		"{event_id}", ctx.EventID,
		"{version}", strconv.FormatInt(ctx.Version, 10),
	)
	return []byte(r.Replace(template))
}

// DecryptPayload déchiffre une charge utile chiffrée en AES-256-GCM avec vérification d'intégrité de l'AAD.
func DecryptPayload(dek []byte, nonceB64, ciphertextB64 string, aad []byte, maxBytes int64) ([]byte, error) {
	if len(dek) != 32 {
		return nil, ErrInvalidKeySize
	}

	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, fmt.Errorf("nonce base64 invalide: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("ciphertext base64 invalide: %w", err)
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("erreur initialisation cipher AES: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("erreur initialisation GCM: %w", err)
	}

	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("taille de nonce invalide (%d octets, attendu %d)", len(nonce), gcm.NonceSize())
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecryptFailed
	}

	if maxBytes > 0 && int64(len(plaintext)) > maxBytes {
		Zeroize(plaintext)
		return nil, ErrPayloadTooLarge
	}

	return plaintext, nil
}
