package pipeline_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"sse-gateway/internal/bus"
	"sse-gateway/internal/config"
	"sse-gateway/internal/crypto"
	"sse-gateway/internal/event"
	"sse-gateway/internal/hub"
	"sse-gateway/internal/pipeline"
	"sse-gateway/internal/testutil"
)

const aadTemplate = "{tenant_id}|{app_id}|{topic_id}|{event_id}|{version}"

// randomBytes produit n octets aléatoires pour les fixtures de test.
func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("génération aléatoire échouée: %v", err)
	}
	return b
}

// newTestConfig construit une configuration minimale de pipeline.
func newTestConfig(aadEnabled bool, maxPayloadBytes int64) *config.Config {
	return &config.Config{
		Crypto: config.CryptoConfig{
			AADEnabled:      aadEnabled,
			AADTemplate:     aadTemplate,
			MaxPayloadBytes: maxPayloadBytes,
		},
		Routing: config.RoutingConfig{
			TopicTemplate: "tenant:{tenant}:app:{app}:topic:{topic}",
		},
	}
}

// newTestProcessor câble un Processor sur un déballeur simulé retournant la DEK fournie.
func newTestProcessor(t *testing.T, cfg *config.Config, dek []byte) *pipeline.Processor {
	t.Helper()
	evRouter, err := event.NewRouter(cfg.Routing.TopicTemplate)
	if err != nil {
		t.Fatalf("initialisation du routeur échouée: %v", err)
	}
	return pipeline.NewProcessor(
		crypto.NewMockUnwrapper(dek),
		hub.NewHub(4, hub.LimitsConfig{}, nil),
		evRouter,
		cfg,
		nil,
		nil,
	)
}

func TestProcessor_DecryptAndBuildFrame_Success(t *testing.T) {
	dek := randomBytes(t, 32)

	// Les deux nonces sont volontairement distincts : celui de l'enveloppe protège la DEK,
	// celui du payload protège le ciphertext applicatif.
	envelopeNonce := randomBytes(t, 12)
	payloadNonce := randomBytes(t, 12)

	cfg := newTestConfig(true, 1024*1024)
	plaintext := []byte(`{"order_id":"12345","amount":99.9}`)

	aad := crypto.BuildAAD(cfg.Crypto.AADTemplate, crypto.AADContext{
		TenantID: "tenant-acme",
		AppID:    "app-store",
		TopicID:  "orders",
		EventID:  "evt-001",
		Version:  1,
	})

	ciphertext, err := testutil.EncryptPayload(dek, payloadNonce, plaintext, aad)
	if err != nil {
		t.Fatalf("échec du chiffrement de test: %v", err)
	}

	proc := newTestProcessor(t, cfg, dek)

	ev := bus.EncryptedEvent{
		EventID:  "evt-001",
		TenantID: "tenant-acme",
		AppID:    "app-store",
		TopicID:  "orders",
		Type:     "order.created",
		Version:  1,
		Crypto: bus.EncryptedPayload{
			SuiteID:      3,
			WrappedKey:   base64.StdEncoding.EncodeToString(dek),
			Nonce:        base64.StdEncoding.EncodeToString(envelopeNonce),
			PayloadNonce: base64.StdEncoding.EncodeToString(payloadNonce),
			Ciphertext:   base64.StdEncoding.EncodeToString(ciphertext),
		},
	}

	frame, err := proc.DecryptAndBuildFrame(context.Background(), ev)
	if err != nil {
		t.Fatalf("déchiffrement attendu avec succès: %v", err)
	}
	if frame == nil || len(frame.Data) == 0 {
		t.Fatal("trame retournée vide")
	}

	frameStr := string(frame.Data)
	if !strings.Contains(frameStr, "order.created") {
		t.Errorf("trame sans type d'événement: %s", frameStr)
	}
	if !strings.Contains(frameStr, "12345") {
		t.Errorf("trame sans payload déchiffré: %s", frameStr)
	}
}

// TestProcessor_MissingPayloadNonce verrouille le rejet en amont, avant tout appel au service
// de déballage : un événement sans crypto.payload_nonce est structurellement invalide.
func TestProcessor_MissingPayloadNonce(t *testing.T) {
	dek := randomBytes(t, 32)
	cfg := newTestConfig(false, 1024*1024)
	proc := newTestProcessor(t, cfg, dek)

	ciphertext, err := testutil.EncryptPayload(dek, randomBytes(t, 12), []byte(`{"a":1}`), nil)
	if err != nil {
		t.Fatalf("échec du chiffrement de test: %v", err)
	}

	ev := bus.EncryptedEvent{
		EventID:  "evt-no-nonce",
		TenantID: "tenant-1",
		AppID:    "app-1",
		TopicID:  "topic-1",
		Crypto: bus.EncryptedPayload{
			WrappedKey: base64.StdEncoding.EncodeToString(dek),
			Nonce:      base64.StdEncoding.EncodeToString(randomBytes(t, 12)),
			Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
			// PayloadNonce volontairement absent
		},
	}

	_, err = proc.DecryptAndBuildFrame(context.Background(), ev)
	if !errors.Is(err, crypto.ErrMissingPayloadNonce) {
		t.Fatalf("attendu crypto.ErrMissingPayloadNonce, obtenu: %v", err)
	}
}

// TestProcessor_EnvelopeNonceIsNotPayloadNonce verrouille la non-régression du bug d'interopérabilité :
// utiliser le nonce d'enveloppe pour déchiffrer le payload doit échouer, jamais réussir par accident.
func TestProcessor_EnvelopeNonceIsNotPayloadNonce(t *testing.T) {
	dek := randomBytes(t, 32)
	envelopeNonce := randomBytes(t, 12)
	payloadNonce := randomBytes(t, 12)

	cfg := newTestConfig(false, 1024*1024)
	ciphertext, err := testutil.EncryptPayload(dek, payloadNonce, []byte(`{"a":1}`), nil)
	if err != nil {
		t.Fatalf("échec du chiffrement de test: %v", err)
	}

	proc := newTestProcessor(t, cfg, dek)

	ev := bus.EncryptedEvent{
		EventID:  "evt-swapped",
		TenantID: "tenant-1",
		AppID:    "app-1",
		TopicID:  "topic-1",
		Crypto: bus.EncryptedPayload{
			WrappedKey: base64.StdEncoding.EncodeToString(dek),
			Nonce:      base64.StdEncoding.EncodeToString(envelopeNonce),
			// Le producteur se trompe et recopie le nonce d'enveloppe.
			PayloadNonce: base64.StdEncoding.EncodeToString(envelopeNonce),
			Ciphertext:   base64.StdEncoding.EncodeToString(ciphertext),
		},
	}

	if _, err := proc.DecryptAndBuildFrame(context.Background(), ev); !errors.Is(err, crypto.ErrDecryptFailed) {
		t.Fatalf("attendu crypto.ErrDecryptFailed avec un nonce erroné, obtenu: %v", err)
	}
}

func TestProcessor_MaxPayloadBytesLimit(t *testing.T) {
	dek := randomBytes(t, 32)
	payloadNonce := randomBytes(t, 12)

	cfg := newTestConfig(false, 10) // Seuil très bas pour provoquer le dépassement
	largePlaintext := []byte("Ce payload fait largement plus de 10 octets")

	ciphertext, err := testutil.EncryptPayload(dek, payloadNonce, largePlaintext, nil)
	if err != nil {
		t.Fatalf("échec du chiffrement de test: %v", err)
	}

	proc := newTestProcessor(t, cfg, dek)

	ev := bus.EncryptedEvent{
		EventID:  "evt-large",
		TenantID: "tenant-1",
		AppID:    "app-1",
		TopicID:  "topic-1",
		Crypto: bus.EncryptedPayload{
			WrappedKey:   base64.StdEncoding.EncodeToString(dek),
			Nonce:        base64.StdEncoding.EncodeToString(randomBytes(t, 12)),
			PayloadNonce: base64.StdEncoding.EncodeToString(payloadNonce),
			Ciphertext:   base64.StdEncoding.EncodeToString(ciphertext),
		},
	}

	if _, err := proc.DecryptAndBuildFrame(context.Background(), ev); !errors.Is(err, crypto.ErrPayloadTooLarge) {
		t.Fatalf("attendu crypto.ErrPayloadTooLarge, obtenu: %v", err)
	}
}
