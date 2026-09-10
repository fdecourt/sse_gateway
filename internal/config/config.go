package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"sse-gateway/internal/auth"
	"sse-gateway/internal/bus/valkey"
	"sse-gateway/internal/crypto"
	cryptohttp "sse-gateway/internal/crypto/httpclient"
	"sse-gateway/internal/hub"
	"sse-gateway/internal/logging"
)

// Config regroupe l'intégralité de la configuration typée et immutable du SSE Gateway.
const (
	DefaultListenPort = 8080
	DefaultHealthPath = "/healthz"
)

type Config struct {
	Environment string
	InstanceID  string
	ServiceName string
	Log         logging.Config
	HTTP        HTTPConfig
	Hub         HubConfig
	Limits      hub.LimitsConfig
	RateLimit   RateLimitConfig
	Heartbeat   HeartbeatConfig
	EventBus    EventBusConfig
	Routing     RoutingConfig
	Crypto      CryptoConfig
	Auth        AuthConfig
	Metrics     MetricsConfig
	Health      HealthConfig
	Shutdown    ShutdownConfig
}

// HTTPConfig regroupe les paramètres du serveur HTTP.
type HTTPConfig struct {
	ListenHost        string
	ListenPort        int
	EventsPath        string
	HealthPath        string
	ReadyPath         string
	MetricsPath       string
	ReadHeaderTimeout time.Duration
	IdleTimeout       time.Duration
	MaxHeaderBytes    int
	WriteTimeout      time.Duration
	TrustProxyHeaders bool
	TrustedProxyCIDRs []string
}

// Address retourne l'adresse réseau d'écoute formatée.
func (h HTTPConfig) Address() string {
	return net.JoinHostPort(h.ListenHost, strconv.Itoa(h.ListenPort))
}

// HubConfig regroupe le paramétrage du Hub et des voies d'événements.
type HubConfig struct {
	Shards             int
	EventLanes         int
	EventLaneQueueSize int
	ClientQueueSize    int
	ClientWriteTimeout time.Duration
	ClientSlowPolicy   hub.SlowPolicy
}

// RateLimitConfig configure la limitation de débit des poignées de main (handshakes).
type RateLimitConfig struct {
	Enabled              bool
	RPS                  float64
	Burst                int
	MaxPendingHandshakes int
	HandshakeTimeout     time.Duration
}

// HeartbeatConfig configure les pings SSE périodiques.
type HeartbeatConfig struct {
	Enabled  bool
	Interval time.Duration
	Payload  string
}

// EventBusConfig configure le bus d'événements sous-jacent.
type EventBusConfig struct {
	Driver string // valkey_pubsub, memory
	Valkey valkey.Config
}

// RoutingConfig configure le gabarit de construction des sujets (topics).
type RoutingConfig struct {
	TopicTemplate string
}

// CryptoConfig configure le fournisseur de déballage de clé et le déchiffrement AES local.
type CryptoConfig struct {
	Driver          string // http, mock
	HTTP            cryptohttp.ClientConfig
	PayloadCipher   string
	MaxPayloadBytes int64
	AADEnabled      bool
	AADTemplate     string
}

// AuthConfig configure la validation des capabilities d'abonnement.
type AuthConfig struct {
	Driver                string // jwt, mock
	JWT                   auth.JWTConfig
	QueryParameter        string
	InvalidationEventType string
}

// MetricsConfig configure l'exposition Prometheus.
type MetricsConfig struct {
	Enabled bool
}

// HealthConfig configure les sondes /healthz et /readyz.
type HealthConfig struct {
	HealthEnabled   bool
	ReadyEnabled    bool
	RequireEventBus bool
	RequireCrypto   bool
}

// ShutdownConfig configure la procédure d'arrêt gracieux.
type ShutdownConfig struct {
	GracePeriod        time.Duration
	StopAcceptingFirst bool
}

// envValue extrait et valide une variable d'environnement avec valeur de repli par défaut.
func envValue[T any](name string, fallback T, parse func(string) (T, error)) (T, error) {
	valStr, ok := os.LookupEnv(name)
	if !ok || strings.TrimSpace(valStr) == "" {
		return fallback, nil
	}
	parsed, err := parse(strings.TrimSpace(valStr))
	if err != nil {
		return fallback, fmt.Errorf("variable d'environnement %s invalide (%q): %w", name, valStr, err)
	}
	return parsed, nil
}

func getEnv(name, fallback string) string {
	val, ok := os.LookupEnv(name)
	if !ok || strings.TrimSpace(val) == "" {
		return fallback
	}
	return strings.TrimSpace(val)
}

// resolveSecret extrait un secret avec priorité accordée au suffixe _FILE (convention Docker secrets).
func resolveSecret(varName string) (string, error) {
	fileVar := varName + "_FILE"
	if filePath, ok := os.LookupEnv(fileVar); ok && strings.TrimSpace(filePath) != "" {
		data, err := os.ReadFile(strings.TrimSpace(filePath))
		if err != nil {
			return "", fmt.Errorf("lecture du fichier secret %s (%s) échouée: %w", fileVar, filePath, err)
		}
		return strings.TrimRight(string(data), "\r\n"), nil
	}
	return os.Getenv(varName), nil
}

func bindEnv[T any](record func(error), target *T, name string, fallback T, parse func(string) (T, error)) {
	val, err := envValue(name, fallback, parse)
	if err != nil {
		record(err)
	} else {
		*target = val
	}
}

// LoadConfig analyse l'ensemble des variables d'environnement SSE_* et construit la configuration validée.
func LoadConfig() (*Config, error) {
	var firstErr error
	record := func(err error) {
		if firstErr == nil && err != nil {
			firstErr = err
		}
	}

	cfg := &Config{}

	// 1. Général
	cfg.Environment = getEnv("SSE_ENVIRONMENT", "production")
	cfg.InstanceID = getEnv("SSE_INSTANCE_ID", "")
	if cfg.InstanceID == "" {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		cfg.InstanceID = hex.EncodeToString(b)
	}
	cfg.ServiceName = getEnv("SSE_SERVICE_NAME", "sse-gateway")

	// 2. Logging
	cfg.Log.Level = getEnv("SSE_LOG_LEVEL", "info")
	cfg.Log.Format = getEnv("SSE_LOG_FORMAT", "json")
	bindEnv(record, &cfg.Log.IncludeSource, "SSE_LOG_INCLUDE_SOURCE", false, strconv.ParseBool)
	bindEnv(record, &cfg.Log.RedactQueryString, "SSE_LOG_REDACT_QUERY_STRING", true, strconv.ParseBool)

	// 3. HTTP
	cfg.HTTP.ListenHost = getEnv("SSE_HTTP_LISTEN_HOST", "0.0.0.0")
	bindEnv(record, &cfg.HTTP.ListenPort, "SSE_HTTP_LISTEN_PORT", DefaultListenPort, strconv.Atoi)
	cfg.HTTP.EventsPath = getEnv("SSE_HTTP_EVENTS_PATH", "/v1/events")
	cfg.HTTP.HealthPath = getEnv("SSE_HTTP_HEALTH_PATH", DefaultHealthPath)
	cfg.HTTP.ReadyPath = getEnv("SSE_HTTP_READY_PATH", "/readyz")
	cfg.HTTP.MetricsPath = getEnv("SSE_HTTP_METRICS_PATH", getEnv("SSE_METRICS_PATH", "/metrics"))

	bindEnv(record, &cfg.HTTP.ReadHeaderTimeout, "SSE_HTTP_READ_HEADER_TIMEOUT", 5*time.Second, time.ParseDuration)
	bindEnv(record, &cfg.HTTP.IdleTimeout, "SSE_HTTP_IDLE_TIMEOUT", 0*time.Second, time.ParseDuration)
	bindEnv(record, &cfg.HTTP.MaxHeaderBytes, "SSE_HTTP_MAX_HEADER_BYTES", 32768, strconv.Atoi)
	bindEnv(record, &cfg.HTTP.WriteTimeout, "SSE_HTTP_WRITE_TIMEOUT", 0*time.Second, time.ParseDuration)
	bindEnv(record, &cfg.HTTP.TrustProxyHeaders, "SSE_HTTP_TRUST_PROXY_HEADERS", false, strconv.ParseBool)

	trustedCIDRs := getEnv("SSE_HTTP_TRUSTED_PROXY_CIDRS", "")
	if trustedCIDRs != "" {
		for _, part := range strings.Split(trustedCIDRs, ",") {
			trimmed := strings.TrimSpace(part)
			if trimmed != "" {
				cfg.HTTP.TrustedProxyCIDRs = append(cfg.HTTP.TrustedProxyCIDRs, trimmed)
			}
		}
	}

	// 4. Hub & Lanes
	bindEnv(record, &cfg.Hub.Shards, "SSE_HUB_SHARDS", 256, strconv.Atoi)
	bindEnv(record, &cfg.Hub.EventLanes, "SSE_EVENT_LANES", 64, strconv.Atoi)
	bindEnv(record, &cfg.Hub.EventLaneQueueSize, "SSE_EVENT_LANE_QUEUE_SIZE", 1024, strconv.Atoi)
	bindEnv(record, &cfg.Hub.ClientQueueSize, "SSE_CLIENT_QUEUE_SIZE", 32, strconv.Atoi)
	bindEnv(record, &cfg.Hub.ClientWriteTimeout, "SSE_CLIENT_WRITE_TIMEOUT", 5*time.Second, time.ParseDuration)
	cfg.Hub.ClientSlowPolicy = hub.SlowPolicy(getEnv("SSE_CLIENT_SLOW_POLICY", "disconnect"))

	// 5. Limits
	bindEnv(record, &cfg.Limits.MaxConnections, "SSE_LIMIT_MAX_CONNECTIONS", 50000, strconv.Atoi)
	bindEnv(record, &cfg.Limits.MaxConnectionsPerUser, "SSE_LIMIT_MAX_CONNECTIONS_PER_USER", 10, strconv.Atoi)
	bindEnv(record, &cfg.Limits.MaxConnectionsPerTenant, "SSE_LIMIT_MAX_CONNECTIONS_PER_TENANT", 0, strconv.Atoi)
	bindEnv(record, &cfg.Limits.MaxTopicsPerConnection, "SSE_LIMIT_MAX_TOPICS_PER_CONNECTION", 64, strconv.Atoi)

	bindEnv(record, &cfg.RateLimit.Enabled, "SSE_CONNECTION_RATE_LIMIT_ENABLED", true, strconv.ParseBool)
	bindEnv(record, &cfg.RateLimit.RPS, "SSE_CONNECTION_RATE_LIMIT_RPS", 100.0, func(s string) (float64, error) {
		return strconv.ParseFloat(s, 64)
	})
	bindEnv(record, &cfg.RateLimit.Burst, "SSE_CONNECTION_RATE_LIMIT_BURST", 200, strconv.Atoi)
	bindEnv(record, &cfg.RateLimit.MaxPendingHandshakes, "SSE_LIMIT_MAX_PENDING_HANDSHAKES", 1000, strconv.Atoi)
	bindEnv(record, &cfg.RateLimit.HandshakeTimeout, "SSE_LIMIT_HANDSHAKE_TIMEOUT", 5*time.Second, time.ParseDuration)

	// 6. Heartbeat
	bindEnv(record, &cfg.Heartbeat.Enabled, "SSE_HEARTBEAT_ENABLED", true, strconv.ParseBool)
	bindEnv(record, &cfg.Heartbeat.Interval, "SSE_HEARTBEAT_INTERVAL", 20*time.Second, time.ParseDuration)
	cfg.Heartbeat.Payload = getEnv("SSE_HEARTBEAT_PAYLOAD", ": ping")

	// 7. Event Bus (Valkey / In-Memory)
	cfg.EventBus.Driver = strings.ToLower(getEnv("SSE_EVENT_BUS_DRIVER", "valkey_pubsub"))
	cfg.EventBus.Valkey.Address = getEnv("SSE_EVENT_BUS_VALKEY_ADDRESS", "valkey:6379")
	cfg.EventBus.Valkey.Username = getEnv("SSE_EVENT_BUS_VALKEY_USERNAME", "")
	if pwd, err := resolveSecret("SSE_EVENT_BUS_VALKEY_PASSWORD"); err != nil {
		record(err)
	} else {
		cfg.EventBus.Valkey.Password = pwd
	}
	bindEnv(record, &cfg.EventBus.Valkey.Database, "SSE_EVENT_BUS_VALKEY_DATABASE", 0, strconv.Atoi)
	bindEnv(record, &cfg.EventBus.Valkey.TLSEnabled, "SSE_EVENT_BUS_VALKEY_TLS_ENABLED", false, strconv.ParseBool)
	cfg.EventBus.Valkey.TLSServerName = getEnv("SSE_EVENT_BUS_VALKEY_TLS_SERVER_NAME", "")
	cfg.EventBus.Valkey.TLSCAFile = getEnv("SSE_EVENT_BUS_VALKEY_TLS_CA_FILE", "")
	cfg.EventBus.Valkey.TLSCertFile = getEnv("SSE_EVENT_BUS_VALKEY_TLS_CERT_FILE", "")
	cfg.EventBus.Valkey.TLSKeyFile = getEnv("SSE_EVENT_BUS_VALKEY_TLS_KEY_FILE", "")
	bindEnv(record, &cfg.EventBus.Valkey.TLSInsecureSkip, "SSE_EVENT_BUS_VALKEY_TLS_INSECURE_SKIP_VERIFY", false, strconv.ParseBool)

	bindEnv(record, &cfg.EventBus.Valkey.ConnectTimeout, "SSE_EVENT_BUS_VALKEY_CONNECT_TIMEOUT", 3*time.Second, time.ParseDuration)
	bindEnv(record, &cfg.EventBus.Valkey.ReadTimeout, "SSE_EVENT_BUS_VALKEY_READ_TIMEOUT", 0*time.Second, time.ParseDuration)
	bindEnv(record, &cfg.EventBus.Valkey.WriteTimeout, "SSE_EVENT_BUS_VALKEY_WRITE_TIMEOUT", 3*time.Second, time.ParseDuration)
	cfg.EventBus.Valkey.ChannelPattern = getEnv("SSE_EVENT_BUS_VALKEY_CHANNEL_PATTERN", "realtime.*")

	bindEnv(record, &cfg.EventBus.Valkey.ReconnectEnabled, "SSE_EVENT_BUS_RECONNECT_ENABLED", true, strconv.ParseBool)
	bindEnv(record, &cfg.EventBus.Valkey.ReconnectMinDelay, "SSE_EVENT_BUS_RECONNECT_MIN_DELAY", 250*time.Millisecond, time.ParseDuration)
	bindEnv(record, &cfg.EventBus.Valkey.ReconnectMaxDelay, "SSE_EVENT_BUS_RECONNECT_MAX_DELAY", 30*time.Second, time.ParseDuration)
	bindEnv(record, &cfg.EventBus.Valkey.ReconnectJitter, "SSE_EVENT_BUS_RECONNECT_JITTER", true, strconv.ParseBool)

	// 8. Routing
	cfg.Routing.TopicTemplate = getEnv("SSE_ROUTING_TOPIC_TEMPLATE", "tenant:{tenant}:app:{app}:topic:{topic}")

	// 9. Crypto & Key Unwrap
	cfg.Crypto.Driver = strings.ToLower(getEnv("SSE_CRYPTO_DRIVER", "http"))
	cfg.Crypto.HTTP.BaseURL = getEnv("SSE_CRYPTO_HTTP_BASE_URL", "http://pq-crypto-microservice:8080")
	cfg.Crypto.HTTP.UnwrapPath = getEnv("SSE_CRYPTO_HTTP_UNWRAP_PATH", "/unwrap-key")
	cfg.Crypto.HTTP.HealthPath = getEnv("SSE_CRYPTO_HTTP_HEALTH_PATH", "/health")
	bindEnv(record, &cfg.Crypto.HTTP.ConnectTimeout, "SSE_CRYPTO_HTTP_CONNECT_TIMEOUT", 1*time.Second, time.ParseDuration)
	bindEnv(record, &cfg.Crypto.HTTP.RequestTimeout, "SSE_CRYPTO_HTTP_REQUEST_TIMEOUT", 3*time.Second, time.ParseDuration)
	bindEnv(record, &cfg.Crypto.HTTP.MaxIdleConns, "SSE_CRYPTO_HTTP_MAX_IDLE_CONNS", 256, strconv.Atoi)
	bindEnv(record, &cfg.Crypto.HTTP.MaxIdleConnsPerHost, "SSE_CRYPTO_HTTP_MAX_IDLE_CONNS_PER_HOST", 256, strconv.Atoi)
	bindEnv(record, &cfg.Crypto.HTTP.IdleConnTimeout, "SSE_CRYPTO_HTTP_IDLE_CONN_TIMEOUT", 90*time.Second, time.ParseDuration)
	cfg.Crypto.HTTP.AuthMode = getEnv("SSE_CRYPTO_HTTP_AUTH_MODE", "none")
	if token, err := resolveSecret("SSE_CRYPTO_HTTP_BEARER_TOKEN"); err != nil {
		record(err)
	} else {
		cfg.Crypto.HTTP.BearerToken = token
	}
	cfg.Crypto.HTTP.BasicUsername = getEnv("SSE_CRYPTO_HTTP_BASIC_USERNAME", "")
	if pass, err := resolveSecret("SSE_CRYPTO_HTTP_BASIC_PASSWORD"); err != nil {
		record(err)
	} else {
		cfg.Crypto.HTTP.BasicPassword = pass
	}

	bindEnv(record, &cfg.Crypto.HTTP.BinaryMode, "SSE_CRYPTO_HTTP_BINARY_MODE", true, strconv.ParseBool)
	bindEnv(record, &cfg.Crypto.HTTP.TLSEnabled, "SSE_CRYPTO_HTTP_TLS_ENABLED", false, strconv.ParseBool)
	cfg.Crypto.HTTP.TLSServerName = getEnv("SSE_CRYPTO_HTTP_TLS_SERVER_NAME", "")
	cfg.Crypto.HTTP.TLSCAFile = getEnv("SSE_CRYPTO_HTTP_TLS_CA_FILE", "")
	cfg.Crypto.HTTP.TLSCertFile = getEnv("SSE_CRYPTO_HTTP_TLS_CERT_FILE", "")
	cfg.Crypto.HTTP.TLSKeyFile = getEnv("SSE_CRYPTO_HTTP_TLS_KEY_FILE", "")
	bindEnv(record, &cfg.Crypto.HTTP.TLSInsecureSkipVerify, "SSE_CRYPTO_HTTP_TLS_INSECURE_SKIP_VERIFY", false, strconv.ParseBool)

	cfg.Crypto.PayloadCipher = getEnv("SSE_CRYPTO_PAYLOAD_CIPHER", "AES-256-GCM")
	bindEnv(record, &cfg.Crypto.MaxPayloadBytes, "SSE_CRYPTO_MAX_PAYLOAD_BYTES", int64(5*1024*1024), func(s string) (int64, error) {
		return strconv.ParseInt(s, 10, 64)
	})
	bindEnv(record, &cfg.Crypto.AADEnabled, "SSE_CRYPTO_AAD_ENABLED", true, strconv.ParseBool)
	cfg.Crypto.AADTemplate = getEnv("SSE_CRYPTO_AAD_TEMPLATE", crypto.DefaultAADTemplate)

	// 10. Auth / Capability
	cfg.Auth.Driver = strings.ToLower(getEnv("SSE_AUTH_DRIVER", "jwt"))
	cfg.Auth.JWT.Algorithm = getEnv("SSE_AUTH_JWT_ALGORITHM", "EdDSA")
	cfg.Auth.JWT.Audience = getEnv("SSE_AUTH_JWT_AUDIENCE", "sse-gateway")
	cfg.Auth.JWT.Issuer = getEnv("SSE_AUTH_JWT_ISSUER", "")
	cfg.Auth.JWT.PublicKeyFile = getEnv("SSE_AUTH_JWT_PUBLIC_KEY_FILE", "")

	if rawPubKey, err := resolveSecret("SSE_AUTH_JWT_PUBLIC_KEY"); err != nil {
		record(err)
	} else if rawPubKey != "" {
		cfg.Auth.JWT.PublicKeyBytes = []byte(rawPubKey)
	}

	if secretKey, err := resolveSecret("SSE_AUTH_JWT_SECRET_KEY"); err != nil {
		record(err)
	} else if secretKey != "" {
		cfg.Auth.JWT.SecretKeyBytes = []byte(secretKey)
	}

	bindEnv(record, &cfg.Auth.JWT.ClockSkew, "SSE_AUTH_JWT_CLOCK_SKEW", 30*time.Second, time.ParseDuration)
	bindEnv(record, &cfg.Auth.JWT.RequireExp, "SSE_AUTH_JWT_REQUIRE_EXP", true, strconv.ParseBool)
	bindEnv(record, &cfg.Auth.JWT.RequireAud, "SSE_AUTH_JWT_REQUIRE_AUD", true, strconv.ParseBool)
	bindEnv(record, &cfg.Auth.JWT.RequireIss, "SSE_AUTH_JWT_REQUIRE_ISS", false, strconv.ParseBool)

	cfg.Auth.QueryParameter = getEnv("SSE_AUTH_QUERY_PARAMETER", "ticket")
	cfg.Auth.InvalidationEventType = getEnv("SSE_AUTH_INVALIDATION_EVENT_TYPE", "auth.invalidate")

	// 11. Metrics & Health
	bindEnv(record, &cfg.Metrics.Enabled, "SSE_METRICS_ENABLED", true, strconv.ParseBool)
	bindEnv(record, &cfg.Health.HealthEnabled, "SSE_HEALTH_ENABLED", true, strconv.ParseBool)
	bindEnv(record, &cfg.Health.ReadyEnabled, "SSE_READY_ENABLED", true, strconv.ParseBool)
	bindEnv(record, &cfg.Health.RequireEventBus, "SSE_READY_REQUIRE_EVENT_BUS", true, strconv.ParseBool)
	bindEnv(record, &cfg.Health.RequireCrypto, "SSE_READY_REQUIRE_CRYPTO", true, strconv.ParseBool)

	// 12. Shutdown
	bindEnv(record, &cfg.Shutdown.GracePeriod, "SSE_SHUTDOWN_GRACE_PERIOD", 30*time.Second, time.ParseDuration)
	bindEnv(record, &cfg.Shutdown.StopAcceptingFirst, "SSE_SHUTDOWN_STOP_ACCEPTING_FIRST", true, strconv.ParseBool)

	if firstErr != nil {
		return nil, firstErr
	}

	return cfg, nil
}

// Validate effectue la validation stricte (fail-fast) de la cohérence de configuration.
func (c *Config) Validate() error {
	if c.HTTP.ListenPort <= 0 || c.HTTP.ListenPort > 65535 {
		return fmt.Errorf("port HTTP invalide: %d (doit être compris entre 1 et 65535)", c.HTTP.ListenPort)
	}
	if c.Hub.Shards <= 0 {
		return errors.New("SSE_HUB_SHARDS doit être strictement supérieur à 0")
	}
	if c.Hub.EventLanes <= 0 {
		return errors.New("SSE_EVENT_LANES doit être strictement supérieur à 0")
	}
	if c.Hub.ClientQueueSize <= 0 {
		return errors.New("SSE_CLIENT_QUEUE_SIZE doit être strictement supérieur à 0")
	}

	switch c.EventBus.Driver {
	case "valkey_pubsub", "memory":
	default:
		return fmt.Errorf("pilote de bus d'événements inconnu: %s (supportés: valkey_pubsub, memory)", c.EventBus.Driver)
	}

	switch c.Crypto.Driver {
	case "http", "mock":
	default:
		return fmt.Errorf("pilote crypto inconnu: %s (supportés: http, mock)", c.Crypto.Driver)
	}

	switch c.Auth.Driver {
	case "jwt", "mock":
	default:
		return fmt.Errorf("pilote d'authentification inconnu: %s (supportés: jwt, mock)", c.Auth.Driver)
	}

	if c.Crypto.PayloadCipher != "" && !strings.EqualFold(c.Crypto.PayloadCipher, "AES-256-GCM") {
		return fmt.Errorf("algorithme de chiffrement payload non supporté: %s (supporté: AES-256-GCM)", c.Crypto.PayloadCipher)
	}

	// Gardes strictes pour l'environnement de production
	if strings.EqualFold(c.Environment, "production") {
		if c.Crypto.Driver == "mock" {
			return errors.New("SSE_CRYPTO_DRIVER=mock est strictement interdit en environnement de production")
		}
		if c.Auth.Driver == "mock" {
			return errors.New("SSE_AUTH_DRIVER=mock est strictement interdit en environnement de production")
		}
		if c.Crypto.HTTP.TLSInsecureSkipVerify {
			return errors.New("SSE_CRYPTO_HTTP_TLS_INSECURE_SKIP_VERIFY=true est strictement interdit en environnement de production")
		}
		if c.EventBus.Valkey.TLSInsecureSkip {
			return errors.New("SSE_EVENT_BUS_VALKEY_TLS_INSECURE_SKIP_VERIFY=true est strictement interdit en environnement de production")
		}
	}

	return nil
}
