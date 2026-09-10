package api

import (
	"log/slog"
	"net/http"

	"sse-gateway/internal/auth"
	"sse-gateway/internal/config"
	"sse-gateway/internal/event"
	"sse-gateway/internal/health"
	"sse-gateway/internal/hub"
	"sse-gateway/internal/metrics"
)

// Router encapsule le multiplexeur HTTP et supervise le cycle de vie des ressources API.
type Router struct {
	http.Handler
	APIHandler *Handler
	limiter    *IPRateLimiter
}

// Close libère proprement les ressources en arrière-plan (zéro fuite de goroutines).
func (r *Router) Close() {
	if r.limiter != nil {
		r.limiter.Stop()
	}
}

// NewRouter initialise le routeur HTTP et applique la chaîne de middlewares durcis.
func NewRouter(
	cfg *config.Config,
	h *hub.Hub,
	val auth.TicketValidator,
	checkers []health.Checker,
	evRouter *event.Router,
	m *metrics.Metrics,
	logger *slog.Logger,
) *Router {
	if logger == nil {
		logger = slog.Default()
	}
	mux := http.NewServeMux()
	handler := NewHandler(cfg, h, val, checkers, evRouter, m, logger)

	var limiter *IPRateLimiter
	var eventsHandler http.Handler = http.HandlerFunc(handler.Events)

	if cfg.RateLimit.Enabled && cfg.RateLimit.RPS > 0 {
		burst := cfg.RateLimit.Burst
		if burst <= 0 {
			burst = 200
		}
		limiter = NewIPRateLimiter(cfg.RateLimit.RPS, burst)
		eventsHandler = RateLimitMiddleware(limiter, cfg.HTTP.TrustProxyHeaders, cfg.HTTP.TrustedProxyCIDRs)(eventsHandler)
	}

	// Enregistrement des routes avec respect des drapeaux d'activation
	mux.Handle(cfg.HTTP.EventsPath, eventsHandler)

	if cfg.Health.HealthEnabled {
		mux.HandleFunc(cfg.HTTP.HealthPath, handler.Healthz)
	}
	if cfg.Health.ReadyEnabled {
		mux.HandleFunc(cfg.HTTP.ReadyPath, handler.Readyz)
	}

	if cfg.Metrics.Enabled && m != nil {
		mux.Handle(cfg.HTTP.MetricsPath, m.Handler())
	}

	// Chaînage des middlewares globaux (TraceMiddleware en tête pour propager trace_id)
	var chain http.Handler = mux
	chain = SecurityHeadersMiddleware(chain)
	chain = RecoveryMiddleware(logger)(chain)
	chain = LoggerMiddleware(logger)(chain)
	chain = TraceMiddleware(chain)

	return &Router{
		Handler:    chain,
		APIHandler: handler,
		limiter:    limiter,
	}
}
