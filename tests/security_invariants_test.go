package tests

import (
	"strings"
	"testing"

	"sse-gateway/internal/hub"
	"sse-gateway/internal/logging"
)

func TestSecurity_QueryStringRedaction(t *testing.T) {
	urlWithSecret := "https://gateway.internal/v1/events?ticket=eyJhbGciOiJFZERTQSI...secret&foo=bar"
	redacted := logging.RedactURL(urlWithSecret)

	if strings.Contains(redacted, "secret") {
		t.Errorf("Le ticket n'a pas été masqué: %s", redacted)
	}
	if !strings.Contains(redacted, "REDACTED") {
		t.Errorf("Le tag de masquage est absent: %s", redacted)
	}
	if !strings.Contains(redacted, "foo=bar") {
		t.Errorf("Les paramètres non sensibles doivent être préservés: %s", redacted)
	}
}

func TestSecurity_InvalidationClosesConnections(t *testing.T) {
	h := hub.NewHub(32, hub.LimitsConfig{}, nil)

	c1 := hub.NewClient("c1", "user-targeted", "tenant-1", []string{"t1"}, 10, hub.SlowPolicyDisconnect, nil)
	c2 := hub.NewClient("c2", "user-targeted", "tenant-1", []string{"t2"}, 10, hub.SlowPolicyDisconnect, nil)
	c3 := hub.NewClient("c3", "user-other", "tenant-1", []string{"t1"}, 10, hub.SlowPolicyDisconnect, nil)

	_ = h.Register(c1, []string{"t1"})
	_ = h.Register(c2, []string{"t2"})
	_ = h.Register(c3, []string{"t1"})

	if h.ActiveConnections() != 3 {
		t.Fatalf("Attendu 3 connexions actives, obtenu %d", h.ActiveConnections())
	}

	// Invalidation ciblée de "user-targeted" sur "tenant-1"
	closedCount := h.InvalidateUser("tenant-1", "user-targeted")

	if closedCount != 2 {
		t.Errorf("Attendu 2 connexions fermées, obtenu %d", closedCount)
	}
	if !c1.IsClosed() || !c2.IsClosed() {
		t.Error("Les connexions c1 et c2 de l'utilisateur révoqué auraient dû être fermées")
	}
	if c3.IsClosed() {
		t.Error("La connexion c3 d'un autre utilisateur ne doit pas être affectée")
	}
	if h.ActiveConnections() != 1 {
		t.Errorf("Attendu 1 connexion restante, obtenu %d", h.ActiveConnections())
	}
}
