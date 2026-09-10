package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics rassemble tous les collecteurs Prometheus requis par la spécification.
type Metrics struct {
	Registry *prometheus.Registry

	ConnectionsActive          prometheus.Gauge
	ConnectionsTotal           prometheus.Counter
	EventsReceivedTotal        prometheus.Counter
	EventsNoSubscriberTotal    prometheus.Counter
	EventsDecryptedTotal       prometheus.Counter
	DecryptErrorsTotal         prometheus.Counter
	FanoutTotal                prometheus.Counter
	FanoutRecipientsTotal      prometheus.Counter
	SlowClientsTotal           prometheus.Counter
	ClientsDisconnectedTotal   prometheus.Counter
	EventBusReconnectsTotal    prometheus.Counter
	CryptoDurationSeconds      prometheus.Histogram
	EventProcessingDuration    prometheus.Histogram
	FanoutDurationSeconds      prometheus.Histogram
	EventLaneQueueDepth        prometheus.Gauge
	EventLaneQueueDroppedTotal prometheus.Counter
}

// NewMetrics instancie et enregistre les métriques Prometheus sans labels à haute cardinalité.
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()

	m := &Metrics{
		Registry: reg,

		ConnectionsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "sse_connections_active",
			Help: "Nombre instantané de connexions SSE ouvertes.",
		}),
		ConnectionsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "sse_connections_total",
			Help: "Nombre total de connexions SSE établies depuis le démarrage.",
		}),
		EventsReceivedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "sse_events_received_total",
			Help: "Nombre total d'événements reçus du bus.",
		}),
		EventsNoSubscriberTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "sse_events_no_subscriber_total",
			Help: "Nombre d'événements ignorés sans déchiffrement faute d'abonnés locaux.",
		}),
		EventsDecryptedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "sse_events_decrypted_total",
			Help: "Nombre total d'événements déchiffrés avec succès.",
		}),
		DecryptErrorsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "sse_decrypt_errors_total",
			Help: "Nombre d'erreurs de déchiffrement ou de déballage de clé.",
		}),
		FanoutTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "sse_fanout_total",
			Help: "Nombre total d'opérations de diffusion (fan-out) effectuées.",
		}),
		FanoutRecipientsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "sse_fanout_recipients_total",
			Help: "Nombre cumulé de trames transmises aux clients individuels.",
		}),
		SlowClientsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "sse_slow_clients_total",
			Help: "Nombre total de clients lents détectés.",
		}),
		ClientsDisconnectedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "sse_clients_disconnected_total",
			Help: "Nombre total de connexions SSE fermées.",
		}),
		EventBusReconnectsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "sse_event_bus_reconnects_total",
			Help: "Nombre de reconnexions de l'adapter EventBus.",
		}),
		CryptoDurationSeconds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "sse_crypto_duration_seconds",
			Help:    "Durée en secondes des opérations de déballage et déchiffrement crypto.",
			Buckets: []float64{0.0005, 0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
		}),
		EventProcessingDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "sse_event_processing_duration_seconds",
			Help:    "Durée totale de traitement de l'événement de la réception au fan-out.",
			Buckets: []float64{0.0005, 0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
		}),
		FanoutDurationSeconds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "sse_fanout_duration_seconds",
			Help:    "Durée de soumission des trames aux canaux clients.",
			Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05},
		}),
		EventLaneQueueDepth: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "sse_event_lane_queue_depth",
			Help: "Profondeur instantanée cumulée des files d'attente des voies d'événements.",
		}),
		EventLaneQueueDroppedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "sse_event_lane_queue_dropped_total",
			Help: "Nombre d'événements rejetés par débordement des files de voies.",
		}),
	}

	reg.MustRegister(
		m.ConnectionsActive,
		m.ConnectionsTotal,
		m.EventsReceivedTotal,
		m.EventsNoSubscriberTotal,
		m.EventsDecryptedTotal,
		m.DecryptErrorsTotal,
		m.FanoutTotal,
		m.FanoutRecipientsTotal,
		m.SlowClientsTotal,
		m.ClientsDisconnectedTotal,
		m.EventBusReconnectsTotal,
		m.CryptoDurationSeconds,
		m.EventProcessingDuration,
		m.FanoutDurationSeconds,
		m.EventLaneQueueDepth,
		m.EventLaneQueueDroppedTotal,
	)

	return m
}

// Handler retourne le gestionnaire HTTP Prometheus standard.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{})
}
