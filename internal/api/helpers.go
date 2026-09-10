package api

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
)

// respondJSON sérialise et transmet une réponse JSON standard avec Content-Type utf-8.
func respondJSON(w http.ResponseWriter, code int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}

// respondError transmet une réponse d'erreur formatée.
func respondError(w http.ResponseWriter, code int, message, details string) {
	respondJSON(w, code, ErrorResponse{
		Error:   message,
		Details: details,
	})
}

// isIPInCIDRs vérifie si une IP appartient à au moins un sous-réseau de confiance.
func isIPInCIDRs(ip net.IP, cidrs []string) bool {
	if ip == nil || len(cidrs) == 0 {
		return false
	}
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil && ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// extractClientIP extrait l'adresse IP cliente distante en validant la chaîne de confiance proxy de droite à gauche.
func extractClientIP(r *http.Request, trustProxy bool, trustedCIDRs []string) string {
	remoteIPStr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteIPStr = r.RemoteAddr
	}

	if !trustProxy {
		return remoteIPStr
	}

	parsedRemote := net.ParseIP(remoteIPStr)

	// Si des CIDRs de proxies de confiance sont configurés, vérifier que le proxy immédiat est de confiance
	if len(trustedCIDRs) > 0 {
		if !isIPInCIDRs(parsedRemote, trustedCIDRs) {
			return remoteIPStr
		}
	}

	// Analyse sécurisée de X-Forwarded-For de droite à gauche (standard RFC 7239 / reverse proxy)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		// Parcourt depuis la fin (l'élément le plus à droite est ajouté par le proxy le plus proche)
		for i := len(parts) - 1; i >= 0; i-- {
			candidate := strings.TrimSpace(parts[i])
			parsed := net.ParseIP(candidate)
			if parsed == nil {
				continue
			}
			// Si on a des CIDRs de confiance et que l'IP est un proxy de confiance, on continue vers la gauche
			if len(trustedCIDRs) > 0 && isIPInCIDRs(parsed, trustedCIDRs) {
				continue
			}
			return candidate
		}
	}

	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		clientIP := strings.TrimSpace(xrip)
		if net.ParseIP(clientIP) != nil {
			return clientIP
		}
	}

	return remoteIPStr
}
