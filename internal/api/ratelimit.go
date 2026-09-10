package api

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// clientLimiter conserve le limiteur et la date de dernière activité pour le garbage collection.
type clientLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// IPRateLimiter gère la limitation de débit (Token Bucket) par adresse IP avec nettoyage automatique.
type IPRateLimiter struct {
	mu      sync.Mutex
	clients map[string]*clientLimiter
	rps     rate.Limit
	burst   int
	stopCh  chan struct{}
}

// NewIPRateLimiter instancie le gestionnaire de rate-limiting par IP.
func NewIPRateLimiter(rps float64, burst int) *IPRateLimiter {
	lim := &IPRateLimiter{
		clients: make(map[string]*clientLimiter),
		rps:     rate.Limit(rps),
		burst:   burst,
		stopCh:  make(chan struct{}),
	}

	// Goroutine de purge périodique des IPs inactives (toutes les 5 minutes)
	go lim.cleanupLoop()

	return lim
}

// GetLimiter récupère ou instancie le rate limiter dédié à une adresse IP spécifique.
func (i *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()

	lim, exists := i.clients[ip]
	if !exists {
		lim = &clientLimiter{
			limiter:  rate.NewLimiter(i.rps, i.burst),
			lastSeen: time.Now(),
		}
		i.clients[ip] = lim
		return lim.limiter
	}

	lim.lastSeen = time.Now()
	return lim.limiter
}

// cleanupLoop supprime les entrées d'adresses IP inactives depuis plus de 10 minutes.
func (i *IPRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-i.stopCh:
			return
		case <-ticker.C:
			i.mu.Lock()
			threshold := time.Now().Add(-10 * time.Minute)
			for ip, lim := range i.clients {
				if lim.lastSeen.Before(threshold) {
					delete(i.clients, ip)
				}
			}
			i.mu.Unlock()
		}
	}
}

// Stop arrête proprement la goroutine d'arrière-plan du limiteur.
func (i *IPRateLimiter) Stop() {
	select {
	case <-i.stopCh:
	default:
		close(i.stopCh)
	}
}
