package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sse-gateway/internal/auth"
	"sse-gateway/internal/config"
	"sse-gateway/internal/event"
	"sse-gateway/internal/health"
	"sse-gateway/internal/hub"
)

type dummyValidator struct{}

func (d *dummyValidator) Validate(ctx context.Context, rawTicket string) (*auth.Capability, error) {
	return &auth.Capability{
		UserID:   "user-1",
		TenantID: "tenant-1",
		AppID:    "app-1",
		Topics:   []string{"topic-1"},
	}, nil
}

func (d *dummyValidator) Health(ctx context.Context) error {
	return nil
}

type slowChecker struct {
	delay time.Duration
	calls atomic.Int64
}

func (s *slowChecker) Name() string { return "slow_service" }

func (s *slowChecker) Check(ctx context.Context) error {
	s.calls.Add(1)
	time.Sleep(s.delay)
	return nil
}

// TestHandler_HandshakeSemaphoreReleasedAfterAdmit valide que le sémaphore de handshake
// est libéré immédiatement dès la fin de l'admission et ne plafonne pas les connexions.
func TestHandler_HandshakeSemaphoreReleasedAfterAdmit(t *testing.T) {
	cfg := &config.Config{
		Limits: hub.LimitsConfig{
			MaxConnections:          100,
			MaxConnectionsPerUser:   100,
			MaxConnectionsPerTenant: 100,
			MaxTopicsPerConnection:  10,
		},
		RateLimit: config.RateLimitConfig{
			MaxPendingHandshakes: 5, // Capacité réduite à 5 pour le test
			HandshakeTimeout:     2 * time.Second,
		},
		Hub: config.HubConfig{
			ClientQueueSize:    16,
			ClientWriteTimeout: 50 * time.Millisecond,
		},
		Auth: config.AuthConfig{
			QueryParameter: "ticket",
		},
	}

	h := hub.NewHub(4, cfg.Limits, nil)
	val := &dummyValidator{}
	router, err := event.NewRouter("tenant:{tenant}:app:{app}:topic:{topic}")
	if err != nil {
		t.Fatalf("NewRouter a échoué: %v", err)
	}
	handler := NewHandler(cfg, h, val, nil, router, nil, nil)

	// Lancer 20 admissions consécutives (supérieures à MaxPendingHandshakes = 5)
	for i := 0; i < 20; i++ {
		req := httptest.NewRequest(http.MethodGet, "/v1/events?ticket=valid-token", nil)
		rec := httptest.NewRecorder()

		client, err := handler.admit(rec, req)
		if err != nil {
			t.Fatalf("admission #%d a échoué inopinément: %v", i, err)
		}
		if client == nil {
			t.Fatalf("client #%d est nil", i)
		}
		// Le sémaphore doit être libre : longueur du canal = 0
		if len(handler.handshakeSem) != 0 {
			t.Fatalf("sémaphore non libéré après admit: %d jetons restants", len(handler.handshakeSem))
		}
	}
}

// TestHandler_ReadyzCacheNonBlocking valide que les lectures de /readyz bénéficient du cache
// et ne subissent pas de contention de verrou pendant les vérifications lentes.
func TestHandler_ReadyzCacheNonBlocking(t *testing.T) {
	cfg := &config.Config{
		ServiceName: "sse-gateway",
		InstanceID:  "test-1",
	}
	checker := &slowChecker{delay: 20 * time.Millisecond}
	handler := NewHandler(cfg, nil, nil, []health.Checker{checker}, nil, nil, nil)

	// Premier appel amorce le cache
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	handler.Readyz(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("attendu 200 OK, reçu %d", rec.Code)
	}
	if checker.calls.Load() != 1 {
		t.Fatalf("attendu 1 appel de sonde, reçu %d", checker.calls.Load())
	}

	// 50 requêtes concurrentes pendant la fenêtre de validité du cache (2s)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest(http.MethodGet, "/readyz", nil)
			w := httptest.NewRecorder()
			handler.Readyz(w, r)
			if w.Code != http.StatusOK {
				t.Errorf("statut readyz inattendu: %d", w.Code)
			}
		}()
	}
	wg.Wait()

	// Les 50 appels ont dû être servis par le cache sans réexécuter la sonde lente
	if checker.calls.Load() != 1 {
		t.Fatalf("les requêtes en cache ont déclenché des sondes superflues: %d appels", checker.calls.Load())
	}
}
