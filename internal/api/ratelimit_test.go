package api

import (
	"testing"
)

func TestIPRateLimiter(t *testing.T) {
	// 5 req/sec, burst de 3
	limiter := NewIPRateLimiter(5, 3)
	defer limiter.Stop()

	ip1 := "192.168.1.10"
	ip2 := "192.168.1.20"

	l1 := limiter.GetLimiter(ip1)
	// Les 3 premières requêtes doivent être acceptées (burst = 3)
	for i := 0; i < 3; i++ {
		if !l1.Allow() {
			t.Fatalf("requête IP1 #%d aurait dû être autorisée", i+1)
		}
	}

	// La 4ème requête doit être refusée immédiatement
	if l1.Allow() {
		t.Fatal("requête IP1 #4 aurait dû être rejetée (dépassement du burst)")
	}

	// Une autre IP (ip2) dispose de son propre seau de jetons indépendant
	l2 := limiter.GetLimiter(ip2)
	if !l2.Allow() {
		t.Fatal("IP2 aurait dû être autorisée (seau indépendant)")
	}
}
