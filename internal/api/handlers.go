package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"sse-gateway/internal/auth"
	"sse-gateway/internal/config"
	"sse-gateway/internal/event"
	"sse-gateway/internal/health"
	"sse-gateway/internal/hub"
	"sse-gateway/internal/metrics"
)

type readyCache struct {
	mu       sync.RWMutex
	probeMu  sync.Mutex
	cachedAt time.Time
	allReady bool
	details  map[string]string
}

// Handler rassemble tous les endpoints HTTP du microservice SSE Gateway.
type Handler struct {
	cfg            *config.Config
	hub            *hub.Hub
	validator      auth.TicketValidator
	checkers       []health.Checker
	router         *event.Router
	metrics        *metrics.Metrics
	logger         *slog.Logger
	startTime      time.Time
	isShuttingDown atomic.Bool
	readyCache     readyCache
	handshakeSem   chan struct{}
}

// NewHandler instancie le gestionnaire d'endpoints HTTP en respectant ISP via []health.Checker.
func NewHandler(
	cfg *config.Config,
	h *hub.Hub,
	val auth.TicketValidator,
	checkers []health.Checker,
	r *event.Router,
	m *metrics.Metrics,
	logger *slog.Logger,
) *Handler {
	if logger == nil {
		logger = slog.Default()
	}

	maxPending := cfg.RateLimit.MaxPendingHandshakes
	if maxPending <= 0 {
		maxPending = 1000
	}

	return &Handler{
		cfg:          cfg,
		hub:          h,
		validator:    val,
		checkers:     checkers,
		router:       r,
		metrics:      m,
		logger:       logger.With("component", "api_handlers"),
		startTime:    time.Now(),
		handshakeSem: make(chan struct{}, maxPending),
	}
}

// SetShuttingDown bascule l'état d'arrêt gracieux pour refuser de nouvelles connexions en amont.
func (h *Handler) SetShuttingDown(shuttingDown bool) {
	h.isShuttingDown.Store(shuttingDown)
}

// admit gère l'admission atomique du client : validation du ticket, vérification des quotas et inscription dans le Hub.
// CONTRAT : En cas d'erreur (retour de nil, err), la réponse HTTP d'erreur a DÉJÀ été sérialisée et transmise au client
// via respondError() ; l'appelant (Events) doit donc simplement retourner sans tenter d'écrire une autre réponse HTTP.
// Le sémaphore de handshake et le contexte de timeout sont libérés par defer dès le retour de cette fonction.
func (h *Handler) admit(w http.ResponseWriter, r *http.Request) (*hub.Client, error) {
	// Contrôle de la saturation des poignées de main (handshakes)
	select {
	case h.handshakeSem <- struct{}{}:
		defer func() { <-h.handshakeSem }()
	default:
		respondError(w, http.StatusServiceUnavailable, "serveur saturé", "le nombre maximal de handshakes simultanés est atteint")
		return nil, errors.New("saturation du sémaphore de handshake")
	}

	// Application du timeout de poignée de main
	handshakeTimeout := h.cfg.RateLimit.HandshakeTimeout
	if handshakeTimeout <= 0 {
		handshakeTimeout = 5 * time.Second
	}
	handshakeCtx, cancelHandshake := context.WithTimeout(r.Context(), handshakeTimeout)
	defer cancelHandshake()

	// 1. Extraction et validation de la capability (ticket)
	ticketParam := h.cfg.Auth.QueryParameter
	if ticketParam == "" {
		ticketParam = "ticket"
	}
	rawTicket := r.URL.Query().Get(ticketParam)
	if rawTicket == "" {
		respondError(w, http.StatusUnauthorized, "ticket manquant", "le paramètre d'URL '"+ticketParam+"' est obligatoire")
		return nil, auth.ErrMissingTicket
	}

	capability, err := h.validator.Validate(handshakeCtx, rawTicket)
	if err != nil {
		h.logger.Warn("Validation du ticket SSE échouée", "remote_addr", r.RemoteAddr, "err", err)
		// Sécurité : masque le détail technique interne pour ne pas fournir d'oracle d'analyse
		respondError(w, http.StatusUnauthorized, "authentification échouée", "ticket invalide ou expiré")
		return nil, err
	}

	// 2. Vérification consultative préalable des quotas
	if err := h.hub.CheckLimits(capability.TenantID, capability.UserID, len(capability.Topics)); err != nil {
		h.logger.Warn("Admission SSE rejetée par dépassement de limite",
			"tenant_id", capability.TenantID,
			"user_id", capability.UserID,
			"err", err,
		)
		respondError(w, http.StatusTooManyRequests, "limite de connexions atteinte", err.Error())
		return nil, err
	}

	// 3. Construction des clés de routage unifiées
	routingKeys := make([]string, len(capability.Topics))
	for i, topic := range capability.Topics {
		routingKeys[i] = h.router.BuildKey(capability.TenantID, capability.AppID, topic)
	}

	// 4. Génération de l'identifiant unique de connexion
	connBytes := make([]byte, 12)
	_, _ = rand.Read(connBytes)
	connectionID := hex.EncodeToString(connBytes)

	// 5. Initialisation du client SSE
	client := hub.NewClient(
		connectionID,
		capability.UserID,
		capability.TenantID,
		routingKeys,
		h.cfg.Hub.ClientQueueSize,
		h.cfg.Hub.ClientSlowPolicy,
		h.hub.NotifySlowClient,
	)

	// Inscription atomique sous verrou unique éliminant toute fenêtre TOCTOU
	if err := h.hub.Register(client, routingKeys); err != nil {
		respondError(w, http.StatusTooManyRequests, "échec d'enregistrement de la connexion", err.Error())
		return nil, err
	}

	return client, nil
}

// Events gère l'ouverture et le maintien des flux Server-Sent Events (/v1/events).
func (h *Handler) Events(w http.ResponseWriter, r *http.Request) {
	if h.isShuttingDown.Load() {
		respondError(w, http.StatusServiceUnavailable, "service en cours d'arrêt", "les nouvelles connexions sont temporairement refusées")
		return
	}

	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "méthode non autorisée", "seule la méthode GET est acceptée pour le flux SSE")
		return
	}

	// Phase d'admission : validation et enregistrement
	client, err := h.admit(w, r)
	if err != nil {
		return
	}
	defer h.hub.Unregister(client)

	// Application des en-têtes canoniques SSE
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("X-Accel-Buffering", "no")

	rc := http.NewResponseController(w)

	writeTimeout := h.cfg.Hub.ClientWriteTimeout
	if writeTimeout <= 0 {
		writeTimeout = 5 * time.Second
	}

	// Émission de la trame initiale "connected" avec échéance d'écriture réelle
	initFrame := hub.NewConnectedFrame(client.ID, int(h.cfg.Heartbeat.Interval.Seconds()))
	_ = rc.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := w.Write(initFrame.Data); err != nil {
		return
	}
	_ = rc.Flush()

	if h.metrics != nil {
		h.metrics.ConnectionsActive.Inc()
		h.metrics.ConnectionsTotal.Inc()
		defer func() {
			h.metrics.ConnectionsActive.Dec()
			h.metrics.ClientsDisconnectedTotal.Inc()
		}()
	}

	h.logger.Info("Connexion SSE établie",
		"connection_id", client.ID,
		"user_id", client.UserID,
		"tenant_id", client.TenantID,
		"topics_count", len(client.Topics),
	)

	// Boucle principale de streaming SSE
	for {
		select {
		case <-r.Context().Done():
			return

		case <-client.Done():
			return

		case frame, ok := <-client.Send:
			if !ok {
				return
			}

			_ = rc.SetWriteDeadline(time.Now().Add(writeTimeout))
			if _, err := w.Write(frame.Data); err != nil {
				return
			}
			_ = rc.Flush()
		}
	}
}

// Healthz répond à la sonde de vitalité (liveness probe).
func (h *Handler) Healthz(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, HealthResponse{
		Status:    "ok",
		Service:   h.cfg.ServiceName,
		Instance:  h.cfg.InstanceID,
		Timestamp: time.Now().UTC(),
		UptimeSec: int64(time.Since(h.startTime).Seconds()),
	})
}

// Readyz répond à la sonde de disponibilité avec mise en cache TTL 2s anti-amplification et sondes non bloquantes.
func (h *Handler) Readyz(w http.ResponseWriter, r *http.Request) {
	if h.isShuttingDown.Load() {
		respondError(w, http.StatusServiceUnavailable, "service en cours d'arrêt", "la passerelle ne dessert plus de trafic")
		return
	}

	// 1. Consultation rapide sous RLock
	h.readyCache.mu.RLock()
	if time.Since(h.readyCache.cachedAt) < 2*time.Second && h.readyCache.details != nil {
		allReady := h.readyCache.allReady
		details := h.readyCache.details
		h.readyCache.mu.RUnlock()
		h.respondReadyz(w, allReady, details)
		return
	}
	h.readyCache.mu.RUnlock()

	// 2. Acquisition du verrou d'exécution de sonde (évite le thundering herd sans bloquer les lecteurs)
	h.readyCache.probeMu.Lock()
	defer h.readyCache.probeMu.Unlock()

	// 3. Double-check au cas où une autre goroutine a rafraîchi le cache pendant l'attente du verrou
	h.readyCache.mu.RLock()
	if time.Since(h.readyCache.cachedAt) < 2*time.Second && h.readyCache.details != nil {
		allReady := h.readyCache.allReady
		details := h.readyCache.details
		h.readyCache.mu.RUnlock()
		h.respondReadyz(w, allReady, details)
		return
	}
	h.readyCache.mu.RUnlock()

	// 4. Exécution des sondes hors du verrou readyCache.mu (aucune contention pour les lectures concurrentes)
	details := make(map[string]string)
	allReady := true

	for _, checker := range h.checkers {
		if checker == nil {
			continue
		}
		if err := checker.Check(r.Context()); err != nil {
			allReady = false
			details[checker.Name()] = err.Error()
		} else {
			details[checker.Name()] = "ok"
		}
	}

	// 5. Mise à jour atomique du cache
	h.readyCache.mu.Lock()
	h.readyCache.cachedAt = time.Now()
	h.readyCache.allReady = allReady
	h.readyCache.details = details
	h.readyCache.mu.Unlock()

	h.respondReadyz(w, allReady, details)
}

func (h *Handler) respondReadyz(w http.ResponseWriter, allReady bool, details map[string]string) {
	status := "ready"
	httpStatus := http.StatusOK
	if !allReady {
		status = "unavailable"
		httpStatus = http.StatusServiceUnavailable
	}

	respondJSON(w, httpStatus, HealthResponse{
		Status:    status,
		Service:   h.cfg.ServiceName,
		Instance:  h.cfg.InstanceID,
		Timestamp: time.Now().UTC(),
		UptimeSec: int64(time.Since(h.startTime).Seconds()),
		Details:   details,
	})
}
