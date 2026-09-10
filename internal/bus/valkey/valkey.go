package valkey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/valkey-io/valkey-go"
	"sse-gateway/internal/bus"
	"sse-gateway/internal/tlsconf"
)

// Config regroupe les paramètres de configuration du bus Valkey Pub/Sub.
type Config struct {
	Address           string // ex: valkey:6379
	Username          string
	Password          string
	Database          int
	TLSEnabled        bool
	TLSServerName     string
	TLSCAFile         string
	TLSCertFile       string
	TLSKeyFile        string
	TLSInsecureSkip   bool
	ConnectTimeout    time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	ChannelPattern    string // ex: realtime.*
	ReconnectEnabled  bool
	ReconnectMinDelay time.Duration // ex: 250ms
	ReconnectMaxDelay time.Duration // ex: 30s
	ReconnectJitter   bool
	BufferSize        int // taille buffer de canal, ex: 1024
}

// Bus est l'adapter EventBus pour Valkey Pub/Sub avec reconnexion automatique.
type Bus struct {
	cfg         Config
	logger      *slog.Logger
	client      valkey.Client
	closeOnce   sync.Once
	closed      atomic.Bool
	subCh       chan bus.EncryptedEvent
	cancel      context.CancelFunc
	reconnectMu sync.RWMutex
	onReconnect func()
}

// NewBus instancie le client Valkey et initialise la structure.
func NewBus(cfg Config, logger *slog.Logger) (*Bus, error) {
	if cfg.Address == "" {
		return nil, errors.New("adresse du serveur Valkey manquante")
	}
	if cfg.ChannelPattern == "" {
		cfg.ChannelPattern = "realtime.*"
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 3 * time.Second
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = 3 * time.Second
	}
	if cfg.ReconnectMinDelay <= 0 {
		cfg.ReconnectMinDelay = 250 * time.Millisecond
	}
	if cfg.ReconnectMaxDelay <= 0 {
		cfg.ReconnectMaxDelay = 30 * time.Second
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 1024
	}
	if logger == nil {
		logger = slog.Default()
	}

	opt := valkey.ClientOption{
		InitAddress: []string{cfg.Address},
		Username:    cfg.Username,
		Password:    cfg.Password,
		SelectDB:    cfg.Database,
		Dialer: net.Dialer{
			Timeout: cfg.ConnectTimeout,
		},
		ConnWriteTimeout: cfg.WriteTimeout,
	}

	if cfg.TLSEnabled {
		tlsConfig, err := tlsconf.Build(tlsconf.Params{
			CertFile:           cfg.TLSCertFile,
			KeyFile:            cfg.TLSKeyFile,
			CAFile:             cfg.TLSCAFile,
			InsecureSkipVerify: cfg.TLSInsecureSkip,
			ServerName:         cfg.TLSServerName,
		})
		if err != nil {
			return nil, fmt.Errorf("configuration TLS Valkey invalide: %w", err)
		}
		opt.TLSConfig = tlsConfig
	}

	client, err := valkey.NewClient(opt)
	if err != nil {
		return nil, fmt.Errorf("création du client Valkey échouée: %w", err)
	}

	return &Bus{
		cfg:    cfg,
		logger: logger.With("component", "valkey_event_bus"),
		client: client,
		subCh:  make(chan bus.EncryptedEvent, cfg.BufferSize),
	}, nil
}

// SetOnReconnect configure le callback exécuté lors de chaque tentative de reconnexion.
// Ce paramètre est généralement configuré au démarrage avant le lancement du trafic.
func (b *Bus) SetOnReconnect(fn func()) {
	b.reconnectMu.Lock()
	defer b.reconnectMu.Unlock()
	b.onReconnect = fn
}

// Subscribe démarre la boucle d'écoute Pub/Sub avec reconnexion avec backoff exponentiel et jitter.
func (b *Bus) Subscribe(ctx context.Context, patterns []string) (<-chan bus.EncryptedEvent, error) {
	if b.closed.Load() {
		return nil, bus.ErrBusClosed
	}

	if len(patterns) == 0 {
		patterns = []string{b.cfg.ChannelPattern}
	}

	loopCtx, cancel := context.WithCancel(ctx)
	b.cancel = cancel

	go b.runSubscribeLoop(loopCtx, patterns)

	return b.subCh, nil
}

// runSubscribeLoop maintient la souscription active et reconnecte en cas d'interruption.
func (b *Bus) runSubscribeLoop(ctx context.Context, patterns []string) {
	var backoffNanos atomic.Int64
	backoffNanos.Store(int64(b.cfg.ReconnectMinDelay))

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for {
		if ctx.Err() != nil || b.closed.Load() {
			return
		}

		b.logger.Info("Souscription Pub/Sub Valkey en cours", "patterns", patterns)
		cmd := b.client.B().Psubscribe().Pattern(patterns...).Build()

		err := b.client.Receive(ctx, cmd, func(msg valkey.PubSubMessage) {
			if b.closed.Load() {
				return
			}
			// Réinitialisation thread-safe du backoff lors de la réception d'un message
			backoffNanos.Store(int64(b.cfg.ReconnectMinDelay))

			var event bus.EncryptedEvent
			if err := json.Unmarshal([]byte(msg.Message), &event); err != nil {
				b.logger.Warn("Événement reçu non sérialisable en JSON, ignoré", "channel", msg.Channel, "err", err)
				return
			}
			event.RawChannel = msg.Channel

			select {
			case b.subCh <- event:
			case <-ctx.Done():
				return
			default:
				b.logger.Warn("Canal de réception d'événements plein, abandon de l'événement (backpressure)", "event_id", event.EventID)
			}
		})

		if ctx.Err() != nil || b.closed.Load() {
			return
		}

		if !b.cfg.ReconnectEnabled {
			b.logger.Warn("Connexion Pub/Sub Valkey interrompue et reconnexion désactivée, arrêt", "err", err)
			return
		}

		b.reconnectMu.RLock()
		reconnectCb := b.onReconnect
		b.reconnectMu.RUnlock()
		if reconnectCb != nil {
			reconnectCb()
		}

		curBackoff := time.Duration(backoffNanos.Load())
		b.logger.Warn("Connexion Pub/Sub Valkey interrompue, tentative de reconnexion...", "err", err, "backoff", curBackoff)

		sleepDuration := curBackoff
		if b.cfg.ReconnectJitter && curBackoff > 2 {
			jitter := time.Duration(rng.Int63n(int64(curBackoff / 2)))
			sleepDuration = curBackoff + jitter
		}

		select {
		case <-time.After(sleepDuration):
		case <-ctx.Done():
			return
		}

		nextBackoff := curBackoff * 2
		if nextBackoff > b.cfg.ReconnectMaxDelay {
			nextBackoff = b.cfg.ReconnectMaxDelay
		}
		backoffNanos.Store(int64(nextBackoff))
	}
}

// Health vérifie que le serveur Valkey répond à la commande PING avec application éventuelle de ReadTimeout.
func (b *Bus) Health(ctx context.Context) error {
	if b.closed.Load() {
		return bus.ErrBusClosed
	}

	checkCtx := ctx
	if b.cfg.ReadTimeout > 0 {
		var cancel context.CancelFunc
		checkCtx, cancel = context.WithTimeout(ctx, b.cfg.ReadTimeout)
		defer cancel()
	}

	err := b.client.Do(checkCtx, b.client.B().Ping().Build()).Error()
	if err != nil {
		return fmt.Errorf("%w: %v", bus.ErrBusUnavailable, err)
	}
	return nil
}

// Check adapte la méthode Health pour satisfaire l'interface health.Checker.
func (b *Bus) Check(ctx context.Context) error {
	return b.Health(ctx)
}

// Name retourne l'identifiant de la sonde.
func (b *Bus) Name() string {
	return "valkey_event_bus"
}

// Close termine proprement les goroutines et ferme le client Valkey sans panique.
func (b *Bus) Close() error {
	b.closeOnce.Do(func() {
		b.closed.Store(true)
		if b.cancel != nil {
			b.cancel()
		}
		b.client.Close()
		// On ne ferme pas b.subCh explicitement afin d'éviter toute panique "send on closed channel"
		// si un callback Receive résiduel est en vol. Le GC s'en chargera naturellement.
	})
	return nil
}
