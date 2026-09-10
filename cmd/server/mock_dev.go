//go:build !production

package main

import (
	"log/slog"

	"sse-gateway/internal/auth"
	"sse-gateway/internal/crypto"
)

func initMockValidator(logger *slog.Logger) auth.TicketValidator {
	logger.Warn("ATTENTION: Utilisation du validateur d'authentification simulé (MOCK) - NE PAS UTILISER EN PRODUCTION")
	return auth.NewMockValidator()
}

func initMockUnwrapper(logger *slog.Logger) crypto.KeyUnwrapper {
	logger.Warn("ATTENTION: Déballage de clé désactivé (MOCK) - NE PAS UTILISER EN PRODUCTION")
	return crypto.NewMockUnwrapper(nil)
}
