package event

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"sse-gateway/internal/bus"
	"sse-gateway/internal/hashutil"
)

// HandlerFunc définit la signature de traitement d'un événement par une voie (lane).
type HandlerFunc func(ctx context.Context, ev bus.EncryptedEvent)

// Dispatcher distribue les événements vers des voies de traitement (lanes) séquentielles par topic.
type Dispatcher struct {
	numLanes     int
	lanes        []chan bus.EncryptedEvent
	handler      HandlerFunc
	logger       *slog.Logger
	wg           sync.WaitGroup
	ctx          context.Context
	cancel       context.CancelFunc
	closed       atomic.Bool
	queueDepth   atomic.Int64
	drainTimeout time.Duration
	mu           sync.RWMutex
}

// NewDispatcher initialise le répartiteur d'événements par voie ordonnée.
func NewDispatcher(numLanes, queueSize int, handler HandlerFunc, logger *slog.Logger) *Dispatcher {
	if numLanes <= 0 {
		numLanes = 64
	}
	if queueSize <= 0 {
		queueSize = 1024
	}
	if logger == nil {
		logger = slog.Default()
	}

	ctx, cancel := context.WithCancel(context.Background())

	d := &Dispatcher{
		numLanes:     numLanes,
		lanes:        make([]chan bus.EncryptedEvent, numLanes),
		handler:      handler,
		logger:       logger.With("component", "event_lanes"),
		ctx:          ctx,
		cancel:       cancel,
		drainTimeout: 10 * time.Second,
	}

	for i := 0; i < numLanes; i++ {
		ch := make(chan bus.EncryptedEvent, queueSize)
		d.lanes[i] = ch
		d.wg.Add(1)
		go d.worker(ch)
	}

	return d
}

// SetDrainTimeout configure le délai maximal accordé au drainage des voies lors de Close().
func (d *Dispatcher) SetDrainTimeout(timeout time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.drainTimeout = timeout
}

// worker consomme séquentiellement les événements assignés à une voie spécifique.
// En cas d'arrêt, il draine les événements en file avec un contexte actif jusqu'à épuisement ou échéance.
func (d *Dispatcher) worker(ch <-chan bus.EncryptedEvent) {
	defer d.wg.Done()

	for ev := range ch {
		d.queueDepth.Add(-1)

		if d.handler != nil {
			// Exécution du traitement de l'événement avec contexte encore valide
			d.handler(d.ctx, ev)
		}
	}
}

// Dispatch achemine l'événement vers la lane correspondant à son topic.
// Protégé par RLock pour garantir l'absence de panique sur canal fermé lors du shutdown.
// Optimisé pour le chemin chaud : incrément atomique O(1) sans verrou global.
func (d *Dispatcher) Dispatch(ev bus.EncryptedEvent) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed.Load() {
		return false
	}

	routingKey := ev.RoutingKey
	if routingKey == "" {
		routingKey = ev.TenantID + ":" + ev.AppID + ":" + ev.TopicID
	}
	laneIdx := hashutil.ShardIndex(routingKey, d.numLanes)
	lane := d.lanes[laneIdx]

	select {
	case lane <- ev:
		d.queueDepth.Add(1)
		return true
	default:
		d.logger.Warn("Queue de la voie d'événements saturée, événement abandonné (backpressure)",
			"lane", laneIdx,
			"topic_id", ev.TopicID,
			"event_id", ev.EventID,
		)
		return false
	}
}

// QueueDepth retourne la profondeur instantanée cumulée des files de toutes les voies en O(1).
func (d *Dispatcher) QueueDepth() int {
	return int(d.queueDepth.Load())
}

// Close arrête proprement les voies sans panique et attend le drainage complet des files
// borné par drainTimeout pour garantir une sortie même en cas de dépendance bloquée.
func (d *Dispatcher) Close() {
	if d.closed.CompareAndSwap(false, true) {
		d.mu.Lock()
		for _, ch := range d.lanes {
			close(ch)
		}
		timeout := d.drainTimeout
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		d.mu.Unlock()

		// Attente bornée du drainage complet
		done := make(chan struct{})
		go func() {
			d.wg.Wait()
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(timeout):
			d.logger.Warn("Drainage des voies d'événements incomplet (échéance atteinte), arrêt forcé",
				"restant", d.QueueDepth(),
				"timeout", timeout,
			)
		}

		// Annulation du contexte pour interrompre tout appel en cours
		d.cancel()
	}
}
