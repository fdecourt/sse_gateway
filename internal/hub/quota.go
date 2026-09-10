package hub

import (
	"errors"
	"fmt"
	"sync"
)

var (
	// ErrMaxConnectionsReached signale que le plafond global de connexions du serveur est atteint.
	ErrMaxConnectionsReached = errors.New("plafond maximal de connexions simultanées atteint sur la passerelle")
	// ErrMaxConnectionsPerUserReached signale qu'un utilisateur a dépassé son quota de connexions autorisées.
	ErrMaxConnectionsPerUserReached = errors.New("nombre maximal de connexions simultanées dépassé pour cet utilisateur")
	// ErrMaxConnectionsPerTenantReached signale qu'un tenant a dépassé son quota alloué.
	ErrMaxConnectionsPerTenantReached = errors.New("nombre maximal de connexions simultanées dépassé pour ce tenant")
)

// QuotaTracker assure le suivi des quotas de connexions et protège contre les conditions de concurrence (TOCTOU).
type QuotaTracker struct {
	mu           sync.Mutex
	activeConns  int64
	userCounts   map[string]int
	tenantCounts map[string]int
	limits       LimitsConfig
}

// NewQuotaTracker initialise le gestionnaire de quotas.
func NewQuotaTracker(limits LimitsConfig) *QuotaTracker {
	return &QuotaTracker{
		userCounts:   make(map[string]int),
		tenantCounts: make(map[string]int),
		limits:       limits,
	}
}

// Check effectue une vérification consultative (lecture seule) des quotas sans incrémenter.
func (q *QuotaTracker) Check(tenantID, userID string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	return q.checkUnderLock(tenantID, userID)
}

// Acquire vérifie et incrémente atomiquement les compteurs sous verrou unique pour éliminer toute fenêtre TOCTOU.
func (q *QuotaTracker) Acquire(tenantID, userID string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if err := q.checkUnderLock(tenantID, userID); err != nil {
		return err
	}

	q.activeConns++
	userKey := tenantID + ":" + userID
	q.userCounts[userKey]++
	if tenantID != "" {
		q.tenantCounts[tenantID]++
	}

	return nil
}

// Release décrémente les compteurs de manière sécurisée.
func (q *QuotaTracker) Release(tenantID, userID string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.activeConns > 0 {
		q.activeConns--
	}

	userKey := tenantID + ":" + userID
	if q.userCounts[userKey] > 0 {
		q.userCounts[userKey]--
		if q.userCounts[userKey] == 0 {
			delete(q.userCounts, userKey)
		}
	}

	if tenantID != "" && q.tenantCounts[tenantID] > 0 {
		q.tenantCounts[tenantID]--
		if q.tenantCounts[tenantID] == 0 {
			delete(q.tenantCounts, tenantID)
		}
	}
}

// ActiveCount retourne le nombre actuel de connexions actives.
func (q *QuotaTracker) ActiveCount() int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.activeConns
}

func (q *QuotaTracker) checkUnderLock(tenantID, userID string) error {
	if q.limits.MaxConnections > 0 && q.activeConns >= int64(q.limits.MaxConnections) {
		return fmt.Errorf("%w (%d)", ErrMaxConnectionsReached, q.limits.MaxConnections)
	}

	if q.limits.MaxConnectionsPerUser > 0 && userID != "" {
		userKey := tenantID + ":" + userID
		if q.userCounts[userKey] >= q.limits.MaxConnectionsPerUser {
			return fmt.Errorf("%w (max: %d)", ErrMaxConnectionsPerUserReached, q.limits.MaxConnectionsPerUser)
		}
	}

	if q.limits.MaxConnectionsPerTenant > 0 && tenantID != "" {
		if q.tenantCounts[tenantID] >= q.limits.MaxConnectionsPerTenant {
			return fmt.Errorf("%w (max: %d)", ErrMaxConnectionsPerTenantReached, q.limits.MaxConnectionsPerTenant)
		}
	}

	return nil
}
