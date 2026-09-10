package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractClientIP(t *testing.T) {
	// Cas 1 : Pas de confiance proxy -> retourne RemoteAddr
	r1 := httptest.NewRequest(http.MethodGet, "/v1/events", nil)
	r1.RemoteAddr = "192.0.2.1:12345"
	r1.Header.Set("X-Forwarded-For", "203.0.113.195, 70.41.3.18")

	ip1 := extractClientIP(r1, false, nil)
	if ip1 != "192.0.2.1" {
		t.Errorf("attendu 192.0.2.1, obtenu %s", ip1)
	}

	// Cas 2 : Confiance proxy sans CIDRs -> prend l'élément de droite (non spoofable par le client)
	r2 := httptest.NewRequest(http.MethodGet, "/v1/events", nil)
	r2.RemoteAddr = "10.0.0.1:12345"
	r2.Header.Set("X-Forwarded-For", "spoofed.client.ip, 198.51.100.42")

	ip2 := extractClientIP(r2, true, nil)
	if ip2 != "198.51.100.42" {
		t.Errorf("attendu 198.51.100.42 (élément de droite), obtenu %s", ip2)
	}

	// Cas 3 : Proxy de confiance avec CIDR -> traverse depuis la droite en sautant le proxy de confiance
	r3 := httptest.NewRequest(http.MethodGet, "/v1/events", nil)
	r3.RemoteAddr = "10.0.0.1:12345"
	r3.Header.Set("X-Forwarded-For", "198.51.100.10, 10.0.0.2")

	trustedCIDRs := []string{"10.0.0.0/8"}
	ip3 := extractClientIP(r3, true, trustedCIDRs)
	if ip3 != "198.51.100.10" {
		t.Errorf("attendu 198.51.100.10 (premier non-proxy depuis la droite), obtenu %s", ip3)
	}

	// Cas 4 : Fallback sur X-Real-IP
	r4 := httptest.NewRequest(http.MethodGet, "/v1/events", nil)
	r4.RemoteAddr = "127.0.0.1:8080"
	r4.Header.Set("X-Real-IP", "198.51.100.99")

	ip4 := extractClientIP(r4, true, nil)
	if ip4 != "198.51.100.99" {
		t.Errorf("attendu 198.51.100.99, obtenu %s", ip4)
	}
}
