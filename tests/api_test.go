package tests

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sse-gateway/internal/api"
	"sse-gateway/internal/auth"
	"sse-gateway/internal/bus/memory"
	"sse-gateway/internal/config"
	"sse-gateway/internal/crypto"
	"sse-gateway/internal/event"
	"sse-gateway/internal/health"
	"sse-gateway/internal/hub"
	"sse-gateway/internal/metrics"
)

func setupTestServer(t *testing.T) (*httptest.Server, *auth.MockValidator, *hub.Hub) {
	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}

	cfg.Auth.Driver = "mock"
	cfg.Crypto.Driver = "mock"
	cfg.EventBus.Driver = "memory"
	cfg.Heartbeat.Interval = 50 * time.Millisecond

	mockVal := auth.NewMockValidator()
	mockCrypto := crypto.NewMockUnwrapper(nil)
	memBus := memory.NewBus(100)
	h := hub.NewHub(16, cfg.Limits, nil)
	m := metrics.NewMetrics()
	evRouter, _ := event.NewRouter(cfg.Routing.TopicTemplate)

	checkers := []health.Checker{memBus, mockCrypto}
	router := api.NewRouter(cfg, h, mockVal, checkers, evRouter, m, nil)
	ts := httptest.NewServer(router.Handler)

	t.Cleanup(func() {
		ts.Close()
		router.Close()
		h.Close()
		memBus.Close()
	})

	return ts, mockVal, h
}

func TestAPI_HealthzAndReadyz(t *testing.T) {
	ts, _, _ := setupTestServer(t)

	// Test /healthz
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Attendu 200 sur /healthz, obtenu %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// Test /readyz
	resp, err = http.Get(ts.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Attendu 200 sur /readyz, obtenu %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestAPI_Events_UnauthorizedWithoutTicket(t *testing.T) {
	ts, _, _ := setupTestServer(t)

	resp, err := http.Get(ts.URL + "/v1/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Attendu 401 sans ticket, obtenu %d", resp.StatusCode)
	}
}

func TestAPI_Events_ConnectAndReceiveInitialFrame(t *testing.T) {
	ts, mockVal, h := setupTestServer(t)

	mockVal.ValidTickets["valid-jwt-token"] = &auth.Capability{
		UserID:    "user-10",
		TenantID:  "tenant-demo",
		AppID:     "app-crm",
		Topics:    []string{"room-42"},
		Audience:  "sse-gateway",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/v1/events?ticket=valid-jwt-token", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Attendu 200 OK pour la connexion SSE, obtenu %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/event-stream") {
		t.Errorf("Content-Type non conforme pour SSE: %s", ct)
	}

	// Lecture de la trame initiale
	reader := bufio.NewReader(resp.Body)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Erreur lecture première ligne: %v", err)
	}

	if !strings.HasPrefix(line, "event: connected") {
		t.Errorf("Attendu event: connected, obtenu: %q", line)
	}

	if h.ActiveConnections() != 1 {
		t.Errorf("Attendu 1 connexion active dans le Hub, obtenu %d", h.ActiveConnections())
	}
}
