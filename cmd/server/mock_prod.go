//go:build production

package main

import (
	"log/slog"

	"sse-gateway/internal/auth"
	"sse-gateway/internal/crypto"
)

func initMockValidator(logger *slog.Logger) auth.TicketValidator {
	logger.Error("Le pilote d'authentification 'mock' est strictement exclu du binaire de production")
	return nil
}

func initMockUnwrapper(logger *slog.Logger) crypto.KeyUnwrapper {
	logger.Error("Le pilote crypto 'mock' est strictement exclu du binaire de production")
	return nil
}
