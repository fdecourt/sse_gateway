package testutil

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

var ErrInvalidKeySize = errors.New("la taille de la clé AES doit être strictement de 32 octets (AES-256)")

// EncryptPayload chiffre une charge utile en AES-256-GCM avec AAD pour les suites de tests et simulations.
// La passerelle de production n'effectue que des déchiffrements ; cette fonction est strictement réservée aux tests.
func EncryptPayload(dek, nonce, plaintext, aad []byte) ([]byte, error) {
	if len(dek) != 32 {
		return nil, ErrInvalidKeySize
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("erreur initialisation cipher AES: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("erreur initialisation GCM: %w", err)
	}
	return gcm.Seal(nil, nonce, plaintext, aad), nil
}
