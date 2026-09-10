package auth

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrMissingTicket signale l'absence du paramètre ticket dans la requête SSE.
	ErrMissingTicket = errors.New("paramètre ticket manquant dans la requête")
	// ErrInvalidTicket signale une signature invalide ou un format de jeton non conforme.
	ErrInvalidTicket = errors.New("ticket d'autorisation invalide ou corrompu")
	// ErrExpiredTicket signale un jeton dont la date d'expiration (exp) est dépassée.
	ErrExpiredTicket = errors.New("ticket d'autorisation expiré")
	// ErrInvalidAudience signale une non-concordance avec l'audience attendue (aud).
	ErrInvalidAudience = errors.New("audience du ticket invalide")
	// ErrInvalidIssuer signale un émetteur (iss) non reconnu.
	ErrInvalidIssuer = errors.New("émetteur du ticket non conforme")
	// ErrMissingClaims signale l'absence des claims obligatoires (tenant_id, app_id ou topics).
	ErrMissingClaims = errors.New("claims obligatoires manquants dans le ticket (tenant_id, app_id ou topics)")
)

// Capability représente le mandat d'abonnement vérifié et validé pour une connexion SSE.
type Capability struct {
	UserID    string    `json:"sub"`
	TenantID  string    `json:"tenant_id"`
	AppID     string    `json:"app_id"`
	Topics    []string  `json:"topics"`
	Audience  string    `json:"aud"`
	Issuer    string    `json:"iss,omitempty"`
	ExpiresAt time.Time `json:"exp"`
}

// TicketValidator isole la validation cryptographique des tickets de capability (JWT, PASETO, Macaroon, etc.).
type TicketValidator interface {
	// Validate vérifie l'intégrité, la signature et les claims du ticket et retourne la Capability autorisée.
	Validate(ctx context.Context, rawTicket string) (*Capability, error)

	// Health vérifie la validité des clés de vérification locales ou du JWKS distant.
	Health(ctx context.Context) error
}
