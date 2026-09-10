package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTConfig configure la validation cryptographique des tickets de session SSE.
type JWTConfig struct {
	Algorithm      string        // EdDSA, RS256, ES256, HS256
	PublicKeyFile  string        // Chemin vers la clé publique PEM
	PublicKeyBytes []byte        // Octets de la clé publique (si injectée directement)
	SecretKeyBytes []byte        // Clé symétrique HMAC (si algorithme HS*)
	Audience       string        // Audience attendue ("aud")
	Issuer         string        // Émetteur requis ("iss")
	ClockSkew      time.Duration // Tolérance d'écart d'horloge
	RequireExp     bool          // Expiration obligatoire ("exp")
	RequireAud     bool          // Audience obligatoire
	RequireIss     bool          // Émetteur obligatoire
}

// CustomClaims représente les revendications (claims) spécifiques au SSE Gateway dans le ticket JWT.
type CustomClaims struct {
	jwt.RegisteredClaims
	TenantID string   `json:"tenant_id"`
	AppID    string   `json:"app_id"`
	Topics   []string `json:"topics"`
}

// JWTValidator implémente TicketValidator en utilisant le standard JWT.
type JWTValidator struct {
	key        any
	parserOpts []jwt.ParserOption
}

// NewJWTValidator instancie le validateur de jetons en normalisant l'algorithme sous sa forme standard.
func NewJWTValidator(cfg JWTConfig) (*JWTValidator, error) {
	if cfg.Algorithm == "" {
		cfg.Algorithm = "EdDSA"
	}
	if cfg.ClockSkew <= 0 {
		cfg.ClockSkew = 30 * time.Second
	}

	var keyBytes []byte
	if len(cfg.PublicKeyBytes) > 0 {
		keyBytes = cfg.PublicKeyBytes
	} else if cfg.PublicKeyFile != "" {
		data, err := os.ReadFile(cfg.PublicKeyFile)
		if err != nil {
			return nil, fmt.Errorf("impossible de lire le fichier de clé publique %s: %w", cfg.PublicKeyFile, err)
		}
		keyBytes = data
	}

	var parsedKey any
	var canonicalAlg string

	switch strings.ToUpper(cfg.Algorithm) {
	case "EDDSA":
		canonicalAlg = "EdDSA"
		if len(keyBytes) == 0 {
			return nil, errors.New("clé publique EdDSA manquante (fichier ou octets requis)")
		}
		pk, err := parseEd25519PublicKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("échec de parsing de clé Ed25519: %w", err)
		}
		parsedKey = pk

	case "RS256", "RS384", "RS512":
		canonicalAlg = strings.ToUpper(cfg.Algorithm)
		if len(keyBytes) == 0 {
			return nil, errors.New("clé publique RSA manquante")
		}
		pk, err := jwt.ParseRSAPublicKeyFromPEM(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("échec de parsing de clé publique RSA: %w", err)
		}
		parsedKey = pk

	case "ES256", "ES384", "ES512":
		canonicalAlg = strings.ToUpper(cfg.Algorithm)
		if len(keyBytes) == 0 {
			return nil, errors.New("clé publique ECDSA manquante")
		}
		pk, err := jwt.ParseECPublicKeyFromPEM(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("échec de parsing de clé publique ECDSA: %w", err)
		}
		parsedKey = pk

	case "HS256", "HS384", "HS512":
		canonicalAlg = strings.ToUpper(cfg.Algorithm)
		if len(cfg.SecretKeyBytes) == 0 && len(keyBytes) == 0 {
			return nil, errors.New("clé secrète HMAC manquante")
		}
		if len(cfg.SecretKeyBytes) > 0 {
			parsedKey = cfg.SecretKeyBytes
		} else {
			parsedKey = keyBytes
		}

	default:
		return nil, fmt.Errorf("algorithme JWT non supporté: %s", cfg.Algorithm)
	}

	parserOpts := []jwt.ParserOption{
		jwt.WithLeeway(cfg.ClockSkew),
		jwt.WithValidMethods([]string{canonicalAlg}),
	}
	if cfg.RequireExp {
		parserOpts = append(parserOpts, jwt.WithExpirationRequired())
	}
	if cfg.RequireAud && cfg.Audience != "" {
		parserOpts = append(parserOpts, jwt.WithAudience(cfg.Audience))
	}
	if cfg.RequireIss && cfg.Issuer != "" {
		parserOpts = append(parserOpts, jwt.WithIssuer(cfg.Issuer))
	}

	return &JWTValidator{
		key:        parsedKey,
		parserOpts: parserOpts,
	}, nil
}

// Validate décode et valide cryptographiquement le ticket JWT reçu en paramètre.
func (v *JWTValidator) Validate(ctx context.Context, rawTicket string) (*Capability, error) {
	if rawTicket == "" {
		return nil, fmt.Errorf("%w: ticket vide", ErrMissingTicket)
	}

	token, err := jwt.ParseWithClaims(
		rawTicket,
		&CustomClaims{},
		func(token *jwt.Token) (any, error) {
			return v.key, nil
		},
		v.parserOpts...,
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, fmt.Errorf("%w: %v", ErrExpiredTicket, err)
		}
		if errors.Is(err, jwt.ErrTokenInvalidAudience) {
			return nil, fmt.Errorf("%w: %v", ErrInvalidAudience, err)
		}
		if errors.Is(err, jwt.ErrTokenInvalidIssuer) {
			return nil, fmt.Errorf("%w: %v", ErrInvalidIssuer, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidTicket, err)
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("%w: signature invalide ou claims manquants", ErrInvalidTicket)
	}

	// Extraction et normalisation des attributs de capacité
	capability := &Capability{
		UserID:   claims.Subject,
		TenantID: claims.TenantID,
		AppID:    claims.AppID,
		Topics:   claims.Topics,
		Issuer:   claims.Issuer,
	}

	if claims.ExpiresAt != nil {
		capability.ExpiresAt = claims.ExpiresAt.Time
	}

	if len(claims.Audience) > 0 {
		capability.Audience = claims.Audience[0]
	}

	// Invariants minimaux : au moins un UserID et un TenantID
	if capability.UserID == "" {
		return nil, fmt.Errorf("%w: claim 'sub' (user_id) obligatoire", ErrMissingClaims)
	}
	if capability.TenantID == "" {
		return nil, fmt.Errorf("%w: claim 'tenant_id' obligatoire", ErrMissingClaims)
	}
	if len(capability.Topics) == 0 {
		return nil, fmt.Errorf("%w: au moins un sujet dans 'topics' est requis", ErrMissingClaims)
	}

	return capability, nil
}

// Health confirme que la clé de validation est correctement instanciée en mémoire.
func (v *JWTValidator) Health(ctx context.Context) error {
	if v.key == nil {
		return errors.New("validateur JWT sans clé active")
	}
	return nil
}

// parseEd25519PublicKey extrait une clé publique Ed25519 à partir de données PEM, Base64 ou brutes (32 octets).
func parseEd25519PublicKey(keyBytes []byte) (ed25519.PublicKey, error) {
	// Tentative 1 : Décodage bloc PEM
	block, _ := pem.Decode(keyBytes)
	if block != nil {
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing PKIX de la clé Ed25519 échoué: %w", err)
		}
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("le bloc PEM fourni n'est pas une clé publique Ed25519 valide")
		}
		return edPub, nil
	}

	// Tentative 2 : Clé brute binaire de 32 octets (RFC 8032)
	if len(keyBytes) == ed25519.PublicKeySize {
		return ed25519.PublicKey(keyBytes), nil
	}

	// Tentative 3 : Encodage Base64 (Standard et URL-safe, avec ou sans padding)
	trimmed := strings.TrimSpace(string(keyBytes))
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}

	for _, enc := range encodings {
		decoded, err := enc.DecodeString(trimmed)
		if err == nil {
			if len(decoded) == ed25519.PublicKeySize {
				return ed25519.PublicKey(decoded), nil
			}
			if pub, err := x509.ParsePKIXPublicKey(decoded); err == nil {
				if edPub, ok := pub.(ed25519.PublicKey); ok {
					return edPub, nil
				}
			}
		}
	}

	return nil, errors.New("format de clé Ed25519 inconnu (attendu: PEM PKIX, Base64 standard/URL ou 32 octets bruts)")
}
