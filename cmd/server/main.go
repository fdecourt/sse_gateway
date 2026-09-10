package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"sse-gateway/internal/api"
	"sse-gateway/internal/auth"
	"sse-gateway/internal/bus"
	busmemory "sse-gateway/internal/bus/memory"
	busvalkey "sse-gateway/internal/bus/valkey"
	"sse-gateway/internal/config"
	"sse-gateway/internal/crypto"
	cryptohttp "sse-gateway/internal/crypto/httpclient"
	"sse-gateway/internal/event"
	"sse-gateway/internal/health"
	"sse-gateway/internal/hub"
	"sse-gateway/internal/logging"
	"sse-gateway/internal/metrics"
	"sse-gateway/internal/pipeline"
)

// Estampilles injectées à la compilation via -ldflags. Les valeurs de repli
// désignent une compilation locale : un binaire non estampillé ne doit jamais
// prétendre porter un numéro de version publié.
var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	// 1. Détection du flag autonome de vérification de santé pour conteneur Docker minimal FROM scratch
	healthcheckFlag := flag.Bool("healthcheck", false, "Exécute un sondage de santé HTTP autonome (retourne 0 si ok, 1 sinon)")
	versionFlag := flag.Bool("version", false, "Affiche la version du binaire")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("SSE Gateway v%s (commit: %s, date: %s)\n", version, commit, buildDate)
		os.Exit(0)
	}

	if *healthcheckFlag {
		port := os.Getenv("SSE_HTTP_LISTEN_PORT")
		if port == "" {
			port = strconv.Itoa(config.DefaultListenPort)
		}
		path := os.Getenv("SSE_HTTP_HEALTH_PATH")
		if path == "" {
			path = config.DefaultHealthPath
		}
		url := fmt.Sprintf("http://127.0.0.1:%s%s", port, path)

		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get(url)
		if err != nil || resp.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		os.Exit(0)
	}

	// 2. Durcissement de l'environnement d'exécution (Linux / POSIX)
	crypto.HardenProcess()

	// 3. Chargement et validation stricte (fail-fast) de la configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		slog.Error("Configuration invalide ou incomplète", "err", err)
		os.Exit(1)
	}
	if err := cfg.Validate(); err != nil {
		slog.Error("Validation de cohérence de configuration échouée", "err", err)
		os.Exit(1)
	}

	// 4. Initialisation du logger structuré
	logger := logging.NewLogger(cfg.Log)
	slog.SetDefault(logger)

	logger.Info("Démarrage du micro-service SSE Gateway",
		"version", version,
		"instance_id", cfg.InstanceID,
		"environment", cfg.Environment,
		"shards", cfg.Hub.Shards,
		"event_lanes", cfg.Hub.EventLanes,
	)

	// 5. Initialisation du registre de métriques Prometheus
	var appMetrics *metrics.Metrics
	if cfg.Metrics.Enabled {
		appMetrics = metrics.NewMetrics()
	}

	// 6. Initialisation du Routeur d'événements
	evRouter, err := event.NewRouter(cfg.Routing.TopicTemplate)
	if err != nil {
		logger.Error("Initialisation du routeur d'événements échouée", "err", err)
		os.Exit(1)
	}

	// 7. Initialisation du Hub SSE shardé
	sseHub := hub.NewHub(cfg.Hub.Shards, cfg.Limits, logger)
	if appMetrics != nil {
		sseHub.SetObservabilityCallbacks(
			func() {
				appMetrics.SlowClientsTotal.Inc()
			},
			func(duration time.Duration) {
				appMetrics.FanoutDurationSeconds.Observe(duration.Seconds())
			},
		)
	}

	// 8. Initialisation du validateur d'authentification (Ticket / Capability)
	var validator auth.TicketValidator
	switch cfg.Auth.Driver {
	case "jwt":
		val, err := auth.NewJWTValidator(cfg.Auth.JWT)
		if err != nil {
			logger.Error("Échec d'initialisation du validateur JWT", "err", err)
			os.Exit(1)
		}
		validator = val
	case "mock":
		validator = initMockValidator(logger)
		if validator == nil {
			logger.Error("Pilote d'authentification mock non supporté dans cette compilation")
			os.Exit(1)
		}
	default:
		logger.Error("Pilote d'authentification non supporté", "driver", cfg.Auth.Driver)
		os.Exit(1)
	}

	// 9. Initialisation de l'adapter Crypto (Key Unwrapping)
	var unwrapper crypto.KeyUnwrapper
	switch cfg.Crypto.Driver {
	case "http":
		client, err := cryptohttp.NewClient(cfg.Crypto.HTTP)
		if err != nil {
			logger.Error("Échec d'initialisation du client crypto HTTP", "err", err)
			os.Exit(1)
		}
		unwrapper = client
	case "mock":
		unwrapper = initMockUnwrapper(logger)
		if unwrapper == nil {
			logger.Error("Pilote crypto mock non supporté dans cette compilation")
			os.Exit(1)
		}
	default:
		logger.Error("Pilote crypto non supporté", "driver", cfg.Crypto.Driver)
		os.Exit(1)
	}

	// 10. Initialisation du Bus d'événements (Valkey Pub/Sub ou In-Memory)
	var eventBus bus.Bus
	switch cfg.EventBus.Driver {
	case "valkey_pubsub":
		b, err := busvalkey.NewBus(cfg.EventBus.Valkey, logger)
		if err != nil {
			logger.Error("Échec de connexion au bus Valkey", "err", err)
			os.Exit(1)
		}
		if appMetrics != nil {
			b.SetOnReconnect(func() {
				appMetrics.EventBusReconnectsTotal.Inc()
			})
		}
		eventBus = b
	case "memory":
		eventBus = busmemory.NewBus(1024)
	default:
		logger.Error("Pilote de bus d'événements non supporté", "driver", cfg.EventBus.Driver)
		os.Exit(1)
	}

	// 11. Initialisation du processeur de pipeline (SRP) et des voies d'événements ordonnées (Event Lanes)
	proc := pipeline.NewProcessor(unwrapper, sseHub, evRouter, cfg, logger, appMetrics)
	dispatcher := event.NewDispatcher(cfg.Hub.EventLanes, cfg.Hub.EventLaneQueueSize, proc.HandleEvent, logger)
	drainBudget := cfg.Shutdown.GracePeriod / 2
	if drainBudget <= 0 {
		drainBudget = 10 * time.Second
	}
	dispatcher.SetDrainTimeout(drainBudget)

	// 12. Démarrage du Heartbeat global
	if cfg.Heartbeat.Enabled {
		sseHub.StartHeartbeat(context.Background(), cfg.Heartbeat.Interval, cfg.Heartbeat.Payload)
		logger.Info("Heartbeat SSE global activé", "interval", cfg.Heartbeat.Interval)
	}

	// 13. Souscription aux flux du Bus d'événements
	busCtx, busCancel := context.WithCancel(context.Background())

	// Échantillonnage périodique de la profondeur des files (hors du chemin chaud, O(1) atomique)
	if appMetrics != nil {
		go func() {
			ticker := time.NewTicker(250 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-busCtx.Done():
					return
				case <-ticker.C:
					appMetrics.EventLaneQueueDepth.Set(float64(dispatcher.QueueDepth()))
				}
			}
		}()
	}

	eventsCh, err := eventBus.Subscribe(busCtx, []string{cfg.EventBus.Valkey.ChannelPattern})
	if err != nil {
		logger.Error("Échec de souscription au flux d'événements du bus", "err", err)
		os.Exit(1)
	}

	var consumerWg sync.WaitGroup
	consumerWg.Add(1)

	// Goroutine de consommation des événements entrants
	go func() {
		defer consumerWg.Done()

		for {
			select {
			case <-busCtx.Done():
				return
			case ev, ok := <-eventsCh:
				if !ok {
					return
				}

				if appMetrics != nil {
					appMetrics.EventsReceivedTotal.Inc()
				}

				if !ev.IsSchemaSupported() {
					logger.Warn("Événement ignoré car version de schéma non supportée",
						"schema", ev.Schema,
						"supported", bus.SupportedEventSchema,
						"event_id", ev.EventID,
					)
					continue
				}

				// Interception des événements système d'invalidation de session
				if ev.Type == cfg.Auth.InvalidationEventType {
					closedCount := sseHub.InvalidateUser(ev.TenantID, ev.UserID)
					logger.Info("Événement auth.invalidate traité",
						"tenant_id", ev.TenantID,
						"user_id", ev.UserID,
						"closed_connections", closedCount,
					)
					continue
				}

				// Vérification rapide s'il existe des abonnés locaux avant d'engager la queue de voie
				// (Optimisation volontaire à deux phases pour épargner la saturation des voies)
				routingKey := evRouter.BuildKey(ev.TenantID, ev.AppID, ev.TopicID)
				if !sseHub.HasSubscribers(routingKey) {
					if appMetrics != nil {
						appMetrics.EventsNoSubscriberTotal.Inc()
					}
					continue
				}

				ev.RoutingKey = routingKey

				// Dispatch vers la voie ordonnée
				if !dispatcher.Dispatch(ev) {
					if appMetrics != nil {
						appMetrics.EventLaneQueueDroppedTotal.Inc()
					}
				}
			}
		}
	}()

	// 14. Préparation des sondes de santé respectant le principe ISP
	var checkers []health.Checker
	if cfg.Health.RequireEventBus {
		if c, ok := eventBus.(health.Checker); ok {
			checkers = append(checkers, c)
		}
	}
	if cfg.Health.RequireCrypto {
		if c, ok := unwrapper.(health.Checker); ok {
			checkers = append(checkers, c)
		}
	}

	// 15. Initialisation du Routeur HTTP et du Serveur
	router := api.NewRouter(cfg, sseHub, validator, checkers, evRouter, appMetrics, logger)
	defer router.Close()

	srv := &http.Server{
		Addr:              cfg.HTTP.Address(),
		Handler:           router.Handler,
		ReadHeaderTimeout: cfg.HTTP.ReadHeaderTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
		MaxHeaderBytes:    cfg.HTTP.MaxHeaderBytes,
		WriteTimeout:      cfg.HTTP.WriteTimeout, // 0 = désactivé au niveau serveur HTTP, géré au niveau connexion via ResponseController
	}

	// 16. Démarrage de l'écoute réseau
	go func() {
		logger.Info("Passerelle SSE prête à recevoir des connexions", "url", fmt.Sprintf("http://%s%s", cfg.HTTP.Address(), cfg.HTTP.EventsPath))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("Erreur critique du serveur HTTP", "err", err)
			os.Exit(1)
		}
	}()

	// 17. Gestion de l'arrêt gracieux ordonné (Graceful Shutdown)
	shutdownSignal := make(chan os.Signal, 1)
	signal.Notify(shutdownSignal, syscall.SIGTERM, syscall.SIGINT)

	sig := <-shutdownSignal
	logger.Info("Signal d'arrêt reçu, amorçage de l'extinction gracieuse...", "signal", sig.String())

	// Étape 1 : Refuser immédiatement les nouvelles connexions en amont si activé
	if cfg.Shutdown.StopAcceptingFirst {
		router.APIHandler.SetShuttingDown(true)
	}

	// Étape 2 : Fermer le serveur HTTP pour couper les requêtes entrantes
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), cfg.Shutdown.GracePeriod)
	defer cancelShutdown()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("Erreur lors de l'arrêt HTTP gracieux, fermeture forcée", "err", err)
		_ = srv.Close()
	}

	// Étape 3 : Arrêt ordonné de la boucle de consommation du bus (arrêt des producteurs)
	busCancel()
	consumerWg.Wait()

	// Étape 4 : Drainage et arrêt complet des voies d'événements (AVANT la fermeture de l'unwrapper)
	dispatcher.Close()

	// Étape 5 : Clôture du bus d'événements et du fournisseur crypto
	_ = eventBus.Close()
	_ = unwrapper.Close()

	// Étape 6 : Fermeture des connexions SSE restantes et arrêt du Hub
	sseHub.Close()

	logger.Info("=== Micro-service SSE Gateway arrêté proprement ===")
}
