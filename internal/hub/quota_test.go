package hub_test

import (
	"sync"
	"testing"

	"sse-gateway/internal/hub"
)

func TestQuotaTracker_LimitsAndTOCTOU(t *testing.T) {
	limits := hub.LimitsConfig{
		MaxConnections:        50,
		MaxConnectionsPerUser: 5,
	}

	qt := hub.NewQuotaTracker(limits)

	// Inscription de 5 connexions pour user-1
	for i := 0; i < 5; i++ {
		if err := qt.Acquire("tenant-1", "user-1"); err != nil {
			t.Fatalf("Acquire %d attendu avec succès: %v", i, err)
		}
	}

	// La 6ème doit être rejetée
	if err := qt.Acquire("tenant-1", "user-1"); err == nil {
		t.Fatal("la 6ème connexion pour user-1 doit être rejetée (max 5)")
	}

	// Libération d'une connexion
	qt.Release("tenant-1", "user-1")

	// Doit pouvoir se réinscrire
	if err := qt.Acquire("tenant-1", "user-1"); err != nil {
		t.Fatalf("Acquire attendu avec succès après release: %v", err)
	}
}

func TestQuotaTracker_ConcurrentBursts(t *testing.T) {
	limits := hub.LimitsConfig{
		MaxConnections:        100,
		MaxConnectionsPerUser: 10,
	}

	qt := hub.NewQuotaTracker(limits)

	// 50 goroutines tentent simultanément de se connecter pour le même utilisateur
	var wg sync.WaitGroup
	successCount := 0
	var mu sync.Mutex

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := qt.Acquire("tenant-1", "user-burst"); err == nil {
				mu.Lock()
				successCount++
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// Sous rafale, exactement 10 doivent réussir, JAMAIS plus (absence totale de TOCTOU)
	if successCount != 10 {
		t.Errorf("TOCTOU détecté ! Succès obtenus: %d (attendu strictement 10)", successCount)
	}
}

func TestHub_UnregisterIdempotence(t *testing.T) {
	limits := hub.LimitsConfig{
		MaxConnections:        10,
		MaxConnectionsPerUser: 2,
	}

	h := hub.NewHub(4, limits, nil)
	client := hub.NewClient("c1", "user-1", "tenant-1", []string{"topic-1"}, 10, hub.SlowPolicyDisconnect, nil)

	if err := h.Register(client, []string{"topic-1"}); err != nil {
		t.Fatalf("Register échoué: %v", err)
	}

	if h.ActiveConnections() != 1 {
		t.Errorf("attendu 1 connexion active, obtenu: %d", h.ActiveConnections())
	}

	// 1. Invalidation via InvalidateUser (ferme et désenregistre le client)
	closed := h.InvalidateUser("tenant-1", "user-1")
	if closed != 1 {
		t.Errorf("attendu 1 client fermé, obtenu: %d", closed)
	}

	if h.ActiveConnections() != 0 {
		t.Errorf("attendu 0 connexions après InvalidateUser, obtenu: %d", h.ActiveConnections())
	}

	// 2. Le defer Unregister(client) du handler HTTP s'exécute à son tour
	h.Unregister(client)

	// Ne doit PAS décrémenter une deuxième fois (vers -1) !
	if h.ActiveConnections() != 0 {
		t.Errorf("double décrément détecté ! ActiveConnections: %d (attendu 0)", h.ActiveConnections())
	}
}
