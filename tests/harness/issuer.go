package harness

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"sse-gateway/internal/auth"
)

// SeedFileName porte la graine Ed25519 (32 octets) de l'autorité de test.
const SeedFileName = "ed25519.seed"

// Capability décrit le droit d'abonnement à graver dans un ticket.
type Capability struct {
	UserID   string
	TenantID string
	AppID    string
	Topics   []string
	TTL      time.Duration // négative pour émettre un ticket déjà expiré
}

// Issuer signe les tickets d'abonnement du banc d'essai. Il tient le rôle du
// service d'autorisation amont : la passerelle ne connaît que la clé publique.
type Issuer struct {
	key ed25519.PrivateKey
}

// NewIssuer charge l'autorité de test depuis le répertoire indiqué.
//
// Elle ne crée jamais de graine : produire des identifiants est la
// responsabilité exclusive de EnsureIssuer, invoquée par « make dev-keys ».
// Cette séparation ferme une classe entière de faux négatifs — un consommateur
// qui génère sa propre clé signerait des tickets que la passerelle rejetterait,
// et le diagnostic (HTTP 401) ne désignerait jamais la cause.
func NewIssuer(dir string) (*Issuer, error) {
	path := filepath.Join(dir, SeedFileName)

	seed, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("identifiants de développement absents de %s — exécutez « make dev-keys »", dir)
		}
		return nil, fmt.Errorf("lecture de la graine %s: %w", path, err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("graine Ed25519 corrompue dans %s: %d octets au lieu de %d",
			path, len(seed), ed25519.SeedSize)
	}
	return &Issuer{key: ed25519.NewKeyFromSeed(seed)}, nil
}

// EnsureIssuer charge l'autorité de test et crée sa graine si elle est absente.
// L'opération est idempotente : réexécuter l'amorçage conserve la clé, donc les
// tickets déjà distribués et la configuration de la passerelle.
func EnsureIssuer(dir string) (*Issuer, error) {
	issuer, err := NewIssuer(dir)
	if err == nil {
		return issuer, nil
	}
	if _, statErr := os.Stat(filepath.Join(dir, SeedFileName)); !os.IsNotExist(statErr) {
		return nil, err
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("création du répertoire d'identifiants %s: %w", dir, err)
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("tirage de la graine Ed25519: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, SeedFileName), seed, 0o600); err != nil {
		return nil, fmt.Errorf("écriture de la graine: %w", err)
	}
	return &Issuer{key: ed25519.NewKeyFromSeed(seed)}, nil
}

// PublicKeyBase64 rend la clé publique au format SubjectPublicKeyInfo encodé en
// Base64, directement consommable par SSE_AUTH_JWT_PUBLIC_KEY.
func (i *Issuer) PublicKeyBase64() (string, error) {
	der, err := x509.MarshalPKIXPublicKey(i.key.Public())
	if err != nil {
		return "", fmt.Errorf("encodage PKIX de la clé publique: %w", err)
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// Mint signe un ticket EdDSA portant la capability demandée. Les revendications
// sont celles du validateur de production : une divergence de schéma ne peut pas
// s'installer sans casser la compilation.
func (i *Issuer) Mint(c Capability) (string, error) {
	now := time.Now()
	claims := auth.CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   c.UserID,
			Audience:  jwt.ClaimStrings{DefaultAudience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-time.Minute)),
			ExpiresAt: jwt.NewNumericDate(now.Add(c.TTL)),
		},
		TenantID: c.TenantID,
		AppID:    c.AppID,
		Topics:   c.Topics,
	}
	return jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(i.key)
}

// DefaultAudience reprend la valeur par défaut de SSE_AUTH_JWT_AUDIENCE.
const DefaultAudience = "sse-gateway"
