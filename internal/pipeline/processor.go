package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"sse-gateway/internal/bus"
	"sse-gateway/internal/config"
	"sse-gateway/internal/crypto"
	"sse-gateway/internal/event"
	"sse-gateway/internal/hub"
	"sse-gateway/internal/metrics"
)

// Processor orchestre le déballage de clé, la vérification AAD, le déchiffrement AES-GCM
// et la sérialisation des trames SSE immuables pour diffusion via le Hub.
type Processor struct {
	unwrapper crypto.KeyUnwrapper
	hub       *hub.Hub
	router    *event.Router
	cfg       *config.Config
	logger    *slog.Logger
	metrics   *metrics.Metrics
}

// NewProcessor instancie le processeur de pipeline d'événements.
func NewProcessor(
	unwrapper crypto.KeyUnwrapper,
	sseHub *hub.Hub,
	router *event.Router,
	cfg *config.Config,
	logger *slog.Logger,
	m *metrics.Metrics,
) *Processor {
	if logger == nil {
		logger = slog.Default()
	}
	return &Processor{
		unwrapper: unwrapper,
		hub:       sseHub,
		router:    router,
		cfg:       cfg,
		logger:    logger.With("component", "pipeline_processor"),
		metrics:   m,
	}
}

// DecryptAndBuildFrame déballe la clé DEK, vérifie l'AAD, déchiffre la charge utile et génère la trame SSE.
// La DEK est systématiquement effacée de la mémoire vive (Zeroize) dès la fin de l'opération.
func (p *Processor) DecryptAndBuildFrame(ctx context.Context, ev bus.EncryptedEvent) (*hub.Frame, error) {
	cryptoStart := time.Now()

	// 0. Validation de schéma en amont : inutile de solliciter le service de déballage
	// (opération KEM coûteuse) si le nonce du payload manque à l'appel.
	if ev.Crypto.PayloadNonce == "" {
		if p.metrics != nil {
			p.metrics.DecryptErrorsTotal.Inc()
		}
		p.logger.Warn("Événement rejeté : nonce de payload absent",
			"event_id", ev.EventID,
			"topic_id", ev.TopicID,
		)
		return nil, crypto.ErrMissingPayloadNonce
	}

	// 1. Déballage de la clé DEK via le provider
	dek, err := p.unwrapper.Unwrap(ctx, ev.ToEnvelope())
	if err != nil {
		if p.metrics != nil {
			p.metrics.DecryptErrorsTotal.Inc()
		}
		p.logger.Warn("Échec du déballage de la clé DEK",
			"event_id", ev.EventID,
			"topic_id", ev.TopicID,
			"err", err,
		)
		return nil, err
	}
	// Invariant de sécurité : destruction immédiate de la DEK en mémoire
	defer crypto.Zeroize(dek)

	// 2. Construction de l'AAD
	var aad []byte
	if p.cfg.Crypto.AADEnabled {
		aad = crypto.BuildAAD(p.cfg.Crypto.AADTemplate, crypto.AADContext{
			TenantID: ev.TenantID,
			AppID:    ev.AppID,
			TopicID:  ev.TopicID,
			EventID:  ev.EventID,
			Version:  ev.Version,
		})
	}

	// 3. Déchiffrement AES-256-GCM local avec borne de taille de payload dédiée
	maxPayloadBytes := p.cfg.Crypto.MaxPayloadBytes
	if maxPayloadBytes <= 0 {
		maxPayloadBytes = 5 * 1024 * 1024 // 5 Mo par défaut
	}

	// Le payload possède son propre nonce, distinct de celui de l'enveloppe consommé par Unwrap.
	plaintext, err := crypto.DecryptPayload(
		dek,
		ev.Crypto.PayloadNonce,
		ev.Crypto.Ciphertext,
		aad,
		maxPayloadBytes,
	)
	if err != nil {
		if p.metrics != nil {
			p.metrics.DecryptErrorsTotal.Inc()
		}
		p.logger.Warn("Échec du déchiffrement du ciphertext AES-GCM",
			"event_id", ev.EventID,
			"err", err,
		)
		return nil, err
	}

	if p.metrics != nil {
		p.metrics.CryptoDurationSeconds.Observe(time.Since(cryptoStart).Seconds())
		p.metrics.EventsDecryptedTotal.Inc()
	}

	// 4. Construction de la charge utile claire
	decryptedPayload := event.DecryptedEventPayload{
		EventID:      ev.EventID,
		TenantID:     ev.TenantID,
		AppID:        ev.AppID,
		TopicID:      ev.TopicID,
		Type:         ev.Type,
		EntityID:     ev.EntityID,
		Version:      ev.Version,
		OriginUserID: ev.OriginUserID,
		CreatedAt:    ev.CreatedAt,
		Data:         json.RawMessage(plaintext),
	}

	serializedJSON, err := json.Marshal(decryptedPayload)
	if err != nil {
		return nil, fmt.Errorf("sérialisation payload déchiffré échouée: %w", err)
	}

	return hub.NewDataFrame(ev.Type, ev.EventID, serializedJSON), nil
}

// HandleEvent traite un événement entrant depuis la voie (lane) et le diffuse conditionnellement via le Hub.
func (p *Processor) HandleEvent(ctx context.Context, ev bus.EncryptedEvent) {
	start := time.Now()
	routingKey := ev.RoutingKey
	if routingKey == "" {
		routingKey = p.router.BuildKey(ev.TenantID, ev.AppID, ev.TopicID)
	}

	recipients, err := p.hub.ConditionalBroadcast(routingKey, func() (*hub.Frame, error) {
		return p.DecryptAndBuildFrame(ctx, ev)
	})

	if err != nil {
		p.logger.Error("Erreur lors de la diffusion conditionnelle de l'événement",
			"event_id", ev.EventID,
			"raw_channel", ev.RawChannel,
			"err", err,
		)
		return
	}

	if p.metrics != nil {
		durationSec := time.Since(start).Seconds()
		p.metrics.EventProcessingDuration.Observe(durationSec)
		if recipients > 0 {
			p.metrics.FanoutTotal.Inc()
			p.metrics.FanoutRecipientsTotal.Add(float64(recipients))
		} else {
			p.metrics.EventsNoSubscriberTotal.Inc()
		}
	}
}
