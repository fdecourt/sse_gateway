package httpclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strings"
	"time"

	"sse-gateway/internal/crypto"
	"sse-gateway/internal/tlsconf"
)

const (
	// unixSchemePrefix déclenche le transport par socket de domaine Unix (ex: unix:///tmp/pq.sock).
	unixSchemePrefix = "unix://"
	// unixLocalHost est l'hôte syntaxique utilisé une fois le transport bascule sur un socket Unix.
	unixLocalHost = "http://localhost"

	// Format binaire V2 du PQC gateway :
	// 'P' | 'Q' | 0x02 | suiteID (uint16 BE) | len(encapKey) (uint16 BE) | encapKey | nonce[12] | wrappedKey
	binaryMagic1     = 'P'
	binaryMagic2     = 'Q'
	binaryFormatV2   = 0x02
	binaryHeaderSize = 7
	gcmNonceSize     = 12
	dekSize          = 32

	contentTypeJSON   = "application/json; charset=utf-8"
	contentTypeBinary = "application/octet-stream"
)

// ClientConfig configure l'adapter HTTP vers le microservice cryptographique externe.
type ClientConfig struct {
	BaseURL               string        // ex: http://pq-crypto-microservice:8080
	UnwrapPath            string        // ex: /unwrap-key
	HealthPath            string        // ex: /health
	ConnectTimeout        time.Duration // ex: 1s
	RequestTimeout        time.Duration // ex: 3s
	MaxIdleConns          int           // ex: 256
	MaxIdleConnsPerHost   int           // ex: 256
	IdleConnTimeout       time.Duration // ex: 90s
	AuthMode              string        // none, bearer, basic
	BearerToken           string
	BasicUsername         string
	BasicPassword         string
	TLSEnabled            bool
	TLSServerName         string
	TLSCAFile             string
	TLSCertFile           string
	TLSKeyFile            string
	TLSInsecureSkipVerify bool
	// BinaryMode privilégie le transport application/octet-stream plutôt que JSON+Base64.
	// La DEK revient alors en octets bruts, effaçables in situ, sans transiter par une
	// chaîne Go immuable que le ramasse-miettes conserve jusqu'à son prochain cycle.
	BinaryMode bool
}

// Client est l'adapter HTTP implémentant crypto.KeyUnwrapper.
type Client struct {
	cfg        ClientConfig
	httpClient *http.Client
	unwrapURL  string
	healthURL  string
}

type unwrapRequest struct {
	Algorithm       string `json:"algorithm,omitempty"`
	Version         string `json:"version,omitempty"`
	SuiteID         uint16 `json:"suite_id,omitempty"`
	EncapsulatedKey string `json:"encapsulated_key"`
	Nonce           string `json:"nonce"`
	WrappedKey      string `json:"wrapped_key"`
}

type unwrapResponse struct {
	PlaintextKey string `json:"plaintext_key"`
	KeyLength    int    `json:"key_length"`
	Error        string `json:"error,omitempty"`
	Details      string `json:"details,omitempty"`
}

// NewClient initialise le client HTTP durci pour le déballage de clés KEM/AES.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("URL de base du service crypto manquante")
	}
	if cfg.UnwrapPath == "" {
		cfg.UnwrapPath = "/unwrap-key"
	}
	if cfg.HealthPath == "" {
		cfg.HealthPath = "/health"
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 3 * time.Second
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 1 * time.Second
	}
	if cfg.MaxIdleConns <= 0 {
		cfg.MaxIdleConns = 256
	}
	if cfg.MaxIdleConnsPerHost <= 0 {
		cfg.MaxIdleConnsPerHost = 256
	}
	if cfg.IdleConnTimeout <= 0 {
		cfg.IdleConnTimeout = 90 * time.Second
	}

	dialer := &net.Dialer{
		Timeout:   cfg.ConnectTimeout,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		DialContext:         dialer.DialContext,
		MaxIdleConns:        cfg.MaxIdleConns,
		MaxIdleConnsPerHost: cfg.MaxIdleConnsPerHost,
		IdleConnTimeout:     cfg.IdleConnTimeout,
		DisableCompression:  true,
		ForceAttemptHTTP2:   true,
	}

	// Transport par socket de domaine Unix : la DEK ne quitte jamais la machine hôte.
	// L'hôte de l'URL devient purement syntaxique, seul le chemin du socket compte.
	socketPath, isUnix := strings.CutPrefix(cfg.BaseURL, unixSchemePrefix)
	if isUnix {
		if socketPath == "" {
			return nil, fmt.Errorf("chemin du socket Unix manquant dans %q", cfg.BaseURL)
		}
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		}
		transport.ForceAttemptHTTP2 = false
		cfg.BaseURL = unixLocalHost
		cfg.TLSEnabled = false
	}

	if cfg.TLSEnabled {
		tlsConfig, err := tlsconf.Build(tlsconf.Params{
			CertFile:           cfg.TLSCertFile,
			KeyFile:            cfg.TLSKeyFile,
			CAFile:             cfg.TLSCAFile,
			InsecureSkipVerify: cfg.TLSInsecureSkipVerify,
			ServerName:         cfg.TLSServerName,
		})
		if err != nil {
			return nil, fmt.Errorf("configuration TLS crypto invalide: %w", err)
		}
		transport.TLSClientConfig = tlsConfig
	}

	base := strings.TrimRight(cfg.BaseURL, "/")
	unwrapPath := "/" + strings.TrimLeft(cfg.UnwrapPath, "/")
	healthPath := "/" + strings.TrimLeft(cfg.HealthPath, "/")

	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   cfg.RequestTimeout,
		},
		unwrapURL: base + unwrapPath,
		healthURL: base + healthPath,
	}, nil
}

// applyAuth injecte les en-têtes d'authentification configurés.
func (c *Client) applyAuth(req *http.Request) {
	switch strings.ToLower(c.cfg.AuthMode) {
	case "bearer":
		if c.cfg.BearerToken != "" {
			req.Header.Set("Authorization", "Bearer "+c.cfg.BearerToken)
		}
	case "basic":
		if c.cfg.BasicUsername != "" || c.cfg.BasicPassword != "" {
			req.SetBasicAuth(c.cfg.BasicUsername, c.cfg.BasicPassword)
		}
	}
}

// Unwrap déballe la clé DEK via l'endpoint HTTP distant.
// En mode binaire, l'enveloppe part en application/octet-stream et la DEK revient en octets bruts.
func (c *Client) Unwrap(ctx context.Context, envelope crypto.WrappedKeyEnvelope) ([]byte, error) {
	if envelope.EncapsulatedKey == "" || envelope.WrappedKey == "" {
		return nil, crypto.ErrInvalidEnvelope
	}

	if c.cfg.BinaryMode {
		return c.unwrapBinary(ctx, envelope)
	}
	return c.unwrapJSON(ctx, envelope)
}

// encodeBinaryEnvelope sérialise l'enveloppe au format binaire V2 attendu par le PQC gateway.
func encodeBinaryEnvelope(envelope crypto.WrappedKeyEnvelope) ([]byte, error) {
	encapKey, err := base64.StdEncoding.DecodeString(envelope.EncapsulatedKey)
	if err != nil {
		return nil, fmt.Errorf("%w: clé encapsulée Base64 invalide: %v", crypto.ErrInvalidEnvelope, err)
	}
	nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return nil, fmt.Errorf("%w: nonce d'enveloppe Base64 invalide: %v", crypto.ErrInvalidEnvelope, err)
	}
	wrappedKey, err := base64.StdEncoding.DecodeString(envelope.WrappedKey)
	if err != nil {
		return nil, fmt.Errorf("%w: clé enveloppée Base64 invalide: %v", crypto.ErrInvalidEnvelope, err)
	}

	if len(nonce) != gcmNonceSize {
		return nil, fmt.Errorf("%w: nonce d'enveloppe de %d octets (attendu %d)", crypto.ErrInvalidEnvelope, len(nonce), gcmNonceSize)
	}
	if len(encapKey) > math.MaxUint16 {
		return nil, fmt.Errorf("%w: clé encapsulée de %d octets, au-delà du champ de longueur 16 bits", crypto.ErrInvalidEnvelope, len(encapKey))
	}

	buf := make([]byte, 0, binaryHeaderSize+len(encapKey)+len(nonce)+len(wrappedKey))
	buf = append(buf, binaryMagic1, binaryMagic2, binaryFormatV2)
	buf = binary.BigEndian.AppendUint16(buf, envelope.SuiteID)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(encapKey)))
	buf = append(buf, encapKey...)
	buf = append(buf, nonce...)
	buf = append(buf, wrappedKey...)

	return buf, nil
}

// unwrapBinary effectue le déballage via le transport octet-stream (zéro Base64, DEK effaçable).
func (c *Client) unwrapBinary(ctx context.Context, envelope crypto.WrappedKeyEnvelope) ([]byte, error) {
	body, err := encodeBinaryEnvelope(envelope)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.unwrapURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("création requête HTTP échouée: %w", err)
	}
	httpReq.Header.Set("Content-Type", contentTypeBinary)
	httpReq.Header.Set("Accept", contentTypeBinary)
	c.applyAuth(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", crypto.ErrCryptoServiceUnavailable, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		// Le gateway répond en JSON pour les erreurs, même sur une requête binaire.
		var errResp unwrapResponse
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		msg := errResp.Error
		if msg == "" {
			msg = resp.Status
		}
		return nil, fmt.Errorf("%w: code HTTP %d (%s)", crypto.ErrUnwrapFailed, resp.StatusCode, msg)
	}

	// Lecture bornée : la DEK fait exactement 32 octets, un octet de plus est une anomalie.
	rawDEK, err := io.ReadAll(io.LimitReader(resp.Body, dekSize+1))
	if err != nil {
		return nil, fmt.Errorf("%w: lecture de la DEK échouée: %v", crypto.ErrUnwrapFailed, err)
	}
	if len(rawDEK) != dekSize {
		crypto.Zeroize(rawDEK)
		return nil, fmt.Errorf("%w: taille de clé DEK invalide (%d octets, attendu %d pour AES-256)", crypto.ErrUnwrapFailed, len(rawDEK), dekSize)
	}

	return rawDEK, nil
}

// unwrapJSON effectue le déballage via le transport JSON+Base64 historique.
func (c *Client) unwrapJSON(ctx context.Context, envelope crypto.WrappedKeyEnvelope) ([]byte, error) {
	reqBody := unwrapRequest{
		Algorithm:       envelope.Algorithm,
		Version:         envelope.Version,
		SuiteID:         envelope.SuiteID,
		EncapsulatedKey: envelope.EncapsulatedKey,
		Nonce:           envelope.Nonce,
		WrappedKey:      envelope.WrappedKey,
	}

	payloadBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("sérialisation requête unwrap échouée: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.unwrapURL, bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("création requête HTTP échouée: %w", err)
	}

	httpReq.Header.Set("Content-Type", contentTypeJSON)
	httpReq.Header.Set("Accept", "application/json")
	c.applyAuth(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", crypto.ErrCryptoServiceUnavailable, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		var errResp unwrapResponse
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		msg := errResp.Error
		if msg == "" {
			msg = resp.Status
		}
		return nil, fmt.Errorf("%w: code HTTP %d (%s)", crypto.ErrUnwrapFailed, resp.StatusCode, msg)
	}

	var unwrapResp unwrapResponse
	if err := json.NewDecoder(resp.Body).Decode(&unwrapResp); err != nil {
		return nil, fmt.Errorf("décodage réponse unwrap échoué: %w", err)
	}

	if unwrapResp.Error != "" {
		return nil, fmt.Errorf("%w: %s (%s)", crypto.ErrUnwrapFailed, unwrapResp.Error, unwrapResp.Details)
	}

	if unwrapResp.PlaintextKey == "" {
		return nil, fmt.Errorf("%w: clé en clair absente de la réponse", crypto.ErrUnwrapFailed)
	}

	rawDEK, err := base64.StdEncoding.DecodeString(unwrapResp.PlaintextKey)
	if err != nil {
		return nil, fmt.Errorf("décodage base64 de la clé DEK échoué: %w", err)
	}

	if len(rawDEK) != dekSize {
		crypto.Zeroize(rawDEK)
		return nil, fmt.Errorf("%w: taille de clé DEK invalide (%d octets, attendu %d pour AES-256)", crypto.ErrUnwrapFailed, len(rawDEK), dekSize)
	}

	return rawDEK, nil
}

// Health vérifie que le service distant de déballage est opérationnel.
func (c *Client) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.healthURL, nil)
	if err != nil {
		return err
	}
	c.applyAuth(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", crypto.ErrCryptoServiceUnavailable, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: code HTTP %d", crypto.ErrCryptoServiceUnavailable, resp.StatusCode)
	}

	return nil
}

// Check adapte la méthode Health pour satisfaire l'interface health.Checker.
func (c *Client) Check(ctx context.Context) error {
	return c.Health(ctx)
}

// Name retourne l'identifiant de la sonde.
func (c *Client) Name() string {
	return "crypto_service"
}

// Close ferme les connexions HTTP inactives.
func (c *Client) Close() error {
	c.httpClient.CloseIdleConnections()
	return nil
}
