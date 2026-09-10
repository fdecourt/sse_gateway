package hub

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"sse-gateway/internal/hashutil"
)

var (
	// ErrMaxTopicsExceeded signale qu'une connexion a demandé plus de topics que le seuil autorisé.
	ErrMaxTopicsExceeded = errors.New("nombre maximal de topics par connexion dépassé")
	// ErrHubClosed signale que le hub est arrêté.
	ErrHubClosed = errors.New("le hub SSE est arrêté")
)

// LimitsConfig regroupe les plafonds de capacité configurables.
type LimitsConfig struct {
	MaxConnections          int
	MaxConnectionsPerUser   int
	MaxConnectionsPerTenant int
	MaxTopicsPerConnection  int
}

// Hub orchestre l'ensemble des shards, le routage fin et le fan-out multi-destinataires.
type Hub struct {
	numShards int
	shards    []*Shard
	limits    LimitsConfig
	logger    *slog.Logger
	closed    atomic.Bool

	// Gestion unifiée et atomique des quotas anti-TOCTOU
	quotas *QuotaTracker

	// Gestion synchronisée du battement de cœur
	heartbeatMu     sync.Mutex
	heartbeatCancel context.CancelFunc

	// Callbacks d'observabilité optionnels
	obsMu        sync.RWMutex
	onSlowClient func()
	onFanout     func(duration time.Duration)
}

// NewHub instancie le Hub avec un découpage en shards indépendants.
func NewHub(numShards int, limits LimitsConfig, logger *slog.Logger) *Hub {
	if numShards <= 0 {
		numShards = 256
	}
	if logger == nil {
		logger = slog.Default()
	}

	h := &Hub{
		numShards: numShards,
		shards:    make([]*Shard, numShards),
		limits:    limits,
		logger:    logger.With("component", "sse_hub"),
		quotas:    NewQuotaTracker(limits),
	}

	for i := 0; i < numShards; i++ {
		h.shards[i] = NewShard()
	}

	return h
}

// SetObservabilityCallbacks injecte les callbacks pour alimenter les métriques Prometheus sans couplage rigide.
// Ce paramètre doit être configuré au démarrage lors du câblage initial, avant le lancement du trafic.
func (h *Hub) SetObservabilityCallbacks(onSlow func(), onFanout func(time.Duration)) {
	h.obsMu.Lock()
	defer h.obsMu.Unlock()
	h.onSlowClient = onSlow
	h.onFanout = onFanout
}

// getShard sélectionne le shard responsable d'une clé de routage via un hachage FNV32a mutualisé.
func (h *Hub) getShard(routingKey string) *Shard {
	idx := hashutil.ShardIndex(routingKey, h.numShards)
	return h.shards[idx]
}

// StartHeartbeat lance la goroutine globale d'émission de battements de cœur périodiques de manière thread-safe.
func (h *Hub) StartHeartbeat(ctx context.Context, interval time.Duration, payload string) {
	if interval <= 0 {
		return
	}

	h.heartbeatMu.Lock()
	defer h.heartbeatMu.Unlock()

	// Arrêt de toute boucle précédente si existante pour éviter toute fuite de goroutine
	if h.heartbeatCancel != nil {
		h.heartbeatCancel()
	}

	hbCtx, cancel := context.WithCancel(ctx)
	h.heartbeatCancel = cancel

	frame := NewHeartbeatFrame(payload)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-hbCtx.Done():
				return
			case <-ticker.C:
				h.BroadcastHeartbeat(frame)
			}
		}
	}()
}

// CheckLimits effectue une vérification préalable non bloquante avant de procéder à l'enregistrement.
func (h *Hub) CheckLimits(tenantID, userID string, topicCount int) error {
	if h.closed.Load() {
		return ErrHubClosed
	}

	if h.limits.MaxTopicsPerConnection > 0 && topicCount > h.limits.MaxTopicsPerConnection {
		return ErrMaxTopicsExceeded
	}

	return h.quotas.Check(tenantID, userID)
}

// Register admet un client et incrémente atomiquement les quotas pour éliminer toute fenêtre TOCTOU.
func (h *Hub) Register(client *Client, routingKeys []string) error {
	if h.closed.Load() {
		return ErrHubClosed
	}

	if h.limits.MaxTopicsPerConnection > 0 && len(routingKeys) > h.limits.MaxTopicsPerConnection {
		return ErrMaxTopicsExceeded
	}

	// Incrément atomique et vérification sous verrou unique
	if err := h.quotas.Acquire(client.TenantID, client.UserID); err != nil {
		return err
	}

	for _, rKey := range routingKeys {
		shard := h.getShard(rKey)
		shard.Register(rKey, client)
	}

	return nil
}

// Unregister détache un client de l'ensemble de ses shards de manière strictement idempotente.
func (h *Hub) Unregister(client *Client) {
	if client == nil {
		return
	}

	// Idempotence garantie : si déjà désenregistré (ex: InvalidateUser ou double appel), retour immédiat
	if !client.MarkUnregistered() {
		return
	}

	client.Close()

	for _, topic := range client.Topics {
		shard := h.getShard(topic)
		shard.Unregister(topic, client.ID)
	}

	h.quotas.Release(client.TenantID, client.UserID)
}

// HasSubscribers vérifie si au moins un abonné local écoute la clé de routage.
func (h *Hub) HasSubscribers(routingKey string) bool {
	return h.getShard(routingKey).HasSubscribers(routingKey)
}

// ConditionalBroadcast applique le déchiffrement conditionnel (Principe d'or de la spécification) :
// Si aucun client local n'est abonné : 0 crypto, 0 déchiffrement AES, 0 allocation, abandon immédiat !
// Si des clients sont présents : exécute le callback une seule fois, puis diffuse la Frame immuable.
func (h *Hub) ConditionalBroadcast(routingKey string, decryptAndBuildFrame func() (*Frame, error)) (int, error) {
	shard := h.getShard(routingKey)

	// Étape 1 : Lookup ultra-rapide des abonnés sous RLock du shard
	recipients := shard.GetRecipients(routingKey)
	if len(recipients) == 0 {
		return 0, nil // DROP immédiat sans aucun coût cryptographique !
	}

	// Étape 2 : Un déchiffrement unique pour toute l'instance
	frame, err := decryptAndBuildFrame()
	if err != nil {
		return 0, err
	}
	if frame == nil {
		return 0, nil
	}

	startFanout := time.Now()

	// Étape 3 : Fan-out non bloquant vers tous les destinataires (hors verrou)
	delivered := 0
	for _, client := range recipients {
		if client.EnqueueFrame(frame) {
			delivered++
		}
	}

	h.obsMu.RLock()
	fanoutCb := h.onFanout
	h.obsMu.RUnlock()
	if fanoutCb != nil {
		fanoutCb(time.Since(startFanout))
	}

	return delivered, nil
}

// BroadcastHeartbeat diffuse le ping périodique à l'ensemble des connexions actives.
func (h *Hub) BroadcastHeartbeat(frame *Frame) {
	for _, shard := range h.shards {
		clients := shard.GetAllClients()
		for _, c := range clients {
			c.EnqueueFrame(frame)
		}
	}
}

// InvalidateUser ferme et déconnecte immédiatement toutes les connexions associées à un utilisateur révoqué.
func (h *Hub) InvalidateUser(tenantID, userID string) int {
	closedCount := 0
	for _, shard := range h.shards {
		matched := shard.InvalidateUser(tenantID, userID)
		for _, c := range matched {
			if c.MarkUnregistered() {
				c.Close()
				h.quotas.Release(c.TenantID, c.UserID)
				closedCount++
			}
		}
	}

	return closedCount
}

// NotifySlowClient enregistre une détection de client lent et déclenche les métriques.
func (h *Hub) NotifySlowClient(c *Client) {
	h.obsMu.RLock()
	slowCb := h.onSlowClient
	h.obsMu.RUnlock()
	if slowCb != nil {
		slowCb()
	}
	h.logger.Warn("Client lent détecté", "client_id", c.ID, "user_id", c.UserID, "policy", c.SlowPolicy)
}

// ActiveConnections retourne le nombre instantané de connexions SSE ouvertes.
func (h *Hub) ActiveConnections() int64 {
	return h.quotas.ActiveCount()
}

// Close arrête le hub, annule le heartbeat et ferme tous les clients.
func (h *Hub) Close() {
	if h.closed.CompareAndSwap(false, true) {
		h.heartbeatMu.Lock()
		if h.heartbeatCancel != nil {
			h.heartbeatCancel()
			h.heartbeatCancel = nil
		}
		h.heartbeatMu.Unlock()

		for _, shard := range h.shards {
			clients := shard.GetAllClients()
			for _, c := range clients {
				c.Close()
			}
		}
	}
}
