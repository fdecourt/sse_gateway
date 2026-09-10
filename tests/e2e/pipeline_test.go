//go:build e2e

// Package e2e valide la chaîne cryptographique complète contre une pile vivante :
// passerelle SSE, bus d'événements Valkey et microservice post-quantique réel.
//
//	make docker-dev   # démarre la pile
//	make test-e2e     # exécute cette suite
//
// Ces tests sont isolés derrière l'étiquette « e2e » afin que `go test ./...`
// reste hermétique et exécutable sans Docker.
package e2e

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"sse-gateway/internal/bus"
	"sse-gateway/internal/crypto"
	"sse-gateway/internal/event"
	"sse-gateway/tests/harness"
)

const (
	// deliveryTimeout borne l'attente d'une trame attendue.
	deliveryTimeout = 15 * time.Second
	// silenceWindow est la fenêtre pendant laquelle on vérifie qu'aucune trame
	// n'est diffusée. Elle doit rester supérieure à la latence de bout en bout
	// nominale, mesurée sous la milliseconde.
	silenceWindow = 2 * time.Second

	tenantID = "tenant-dev"
	appID    = "app-dev"
	topicID  = "orders"
)

// rig regroupe les dépendances partagées par les tests de la suite.
type rig struct {
	env       harness.Environment
	issuer    *harness.Issuer
	publisher *harness.Publisher
}

// newRig prépare le banc d'essai et échoue immédiatement, avec une consigne
// actionnable, si la pile n'est pas joignable.
func newRig(t *testing.T) *rig {
	t.Helper()

	env := harness.LoadEnvironment()
	if err := probe(env.GatewayURL + "/readyz"); err != nil {
		t.Fatalf("pile indisponible sur %s (%v)\nDémarrez-la avec « make docker-dev ».", env.GatewayURL, err)
	}

	issuer, err := harness.NewIssuer(env.KeyDir)
	if err != nil {
		t.Fatalf("autorité de test: %v", err)
	}

	publisher, err := harness.NewPublisher(env)
	if err != nil {
		t.Fatalf("producteur d'événements: %v", err)
	}
	t.Cleanup(publisher.Close)

	return &rig{env: env, issuer: issuer, publisher: publisher}
}

func probe(url string) error {
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// subscriber ouvre un flux abonné au sujet nominal.
func (r *rig) subscriber(t *testing.T) *harness.Stream {
	t.Helper()

	ticket := r.mint(t, harness.Capability{
		UserID:   "e2e-subscriber",
		TenantID: tenantID,
		AppID:    appID,
		Topics:   []string{topicID},
		TTL:      time.Hour,
	})

	stream, err := harness.Open(r.env.GatewayURL, ticket, 64)
	if err != nil {
		t.Fatalf("ouverture du flux SSE: %v", err)
	}
	t.Cleanup(stream.Close)

	if _, ok := stream.AwaitConnected(deliveryTimeout); !ok {
		t.Fatal("accusé de connexion jamais reçu")
	}
	return stream
}

func (r *rig) mint(t *testing.T, c harness.Capability) string {
	t.Helper()
	ticket, err := r.issuer.Mint(c)
	if err != nil {
		t.Fatalf("signature du ticket: %v", err)
	}
	return ticket
}

func (r *rig) scrape(t *testing.T) harness.Snapshot {
	t.Helper()
	snapshot, err := harness.Scrape(r.env.GatewayURL)
	if err != nil {
		t.Fatalf("relevé Prometheus: %v", err)
	}
	return snapshot
}

func (r *rig) publish(t *testing.T, ev harness.Event) bus.EncryptedEvent {
	t.Helper()
	published, err := r.publisher.Publish(context.Background(), ev)
	if err != nil {
		t.Fatalf("publication de l'événement %s: %v", ev.EventID, err)
	}
	return published
}

// eventID produit un identifiant unique par cas de test.
func eventID(t *testing.T) string {
	t.Helper()
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatalf("tirage d'identifiant: %v", err)
	}
	return t.Name() + "-" + base64.RawURLEncoding.EncodeToString(suffix)
}

// TestTicketAdmission vérifie le contrôle d'accès à l'ouverture du flux.
func TestTicketAdmission(t *testing.T) {
	r := newRig(t)

	valid := harness.Capability{
		UserID: "e2e-admission", TenantID: tenantID, AppID: appID,
		Topics: []string{topicID}, TTL: time.Hour,
	}

	cases := []struct {
		name       string
		ticket     string
		wantStatus int // 0 signifie admission attendue
	}{
		{name: "ticket absent", ticket: "", wantStatus: http.StatusUnauthorized},
		{name: "signature falsifiée", ticket: "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJwaXJhdGUifQ.falsifie", wantStatus: http.StatusUnauthorized},
		{name: "ticket expiré", ticket: r.mint(t, withTTL(valid, -time.Minute)), wantStatus: http.StatusUnauthorized},
		{name: "revendication topics vide", ticket: r.mint(t, withTopics(valid)), wantStatus: http.StatusUnauthorized},
		{name: "ticket EdDSA valide", ticket: r.mint(t, valid)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stream, err := harness.Open(r.env.GatewayURL, tc.ticket, 8)
			if stream != nil {
				defer stream.Close()
			}

			if tc.wantStatus == 0 {
				if err != nil {
					t.Fatalf("admission refusée alors qu'elle était attendue: %v", err)
				}
				if got := stream.Header().Get("Content-Type"); got != "text/event-stream; charset=utf-8" {
					t.Errorf("Content-Type = %q, attendu text/event-stream; charset=utf-8", got)
				}
				if _, ok := stream.AwaitConnected(deliveryTimeout); !ok {
					t.Error("accusé de connexion jamais reçu")
				}
				return
			}

			var refusal *harness.HandshakeError
			if !errors.As(err, &refusal) {
				t.Fatalf("erreur = %v, attendu un refus d'admission", err)
			}
			if refusal.StatusCode != tc.wantStatus {
				t.Errorf("statut = %d, attendu %d", refusal.StatusCode, tc.wantStatus)
			}
		})
	}
}

// TestEncryptedEventDelivery valide le chemin nominal : un événement scellé sous
// ML-KEM-1024 puis AES-256-GCM revient au client, déchiffré et intact.
func TestEncryptedEventDelivery(t *testing.T) {
	r := newRig(t)
	stream := r.subscriber(t)

	cases := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "charge utile applicative",
			payload: []byte(`{"order_id":"A-1024","amount":42.5,"currency":"EUR"}`),
		},
		{
			name:    "charge utile volumineuse",
			payload: largePayload(t, 256<<10),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := eventID(t)
			eventType := "order.created"

			published := r.publish(t, harness.Event{
				TenantID: tenantID, AppID: appID, TopicID: topicID,
				Type: eventType, EventID: id, Version: 7, Payload: tc.payload,
			})

			assertRealKEMEnvelope(t, published)

			frame, ok := stream.Await(eventType, deliveryTimeout)
			if !ok {
				t.Fatalf("aucune trame %q reçue en %s", eventType, deliveryTimeout)
			}
			if frame.ID != id {
				t.Errorf("identifiant de trame = %q, attendu %q", frame.ID, id)
			}

			var decrypted event.DecryptedEventPayload
			if err := json.Unmarshal([]byte(frame.Data), &decrypted); err != nil {
				t.Fatalf("charge utile de trame illisible: %v", err)
			}
			if string(decrypted.Data) != string(tc.payload) {
				t.Errorf("charge utile déchiffrée de %d octets, %d attendus — le clair diffère",
					len(decrypted.Data), len(tc.payload))
			}
			if decrypted.TenantID != tenantID || decrypted.AppID != appID ||
				decrypted.TopicID != topicID || decrypted.Version != 7 {
				t.Errorf("métadonnées de routage altérées: %+v", decrypted)
			}
		})
	}
}

// TestCryptographicInvariants vérifie qu'aucune altération d'enveloppe ne
// produit de diffusion, et que chaque rejet est comptabilisé.
func TestCryptographicInvariants(t *testing.T) {
	r := newRig(t)
	stream := r.subscriber(t)

	// Enveloppe ML-KEM sans rapport, servant à la substitution.
	foreign, err := r.publisher.Seal(context.Background(), harness.Event{
		TenantID: tenantID, AppID: appID, TopicID: topicID,
		Type: "unused", EventID: "foreign-envelope", Payload: []byte(`{}`),
	})
	if err != nil {
		t.Fatalf("préparation de l'enveloppe étrangère: %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(*harness.Event)
		counter string
	}{
		{
			name:    "chiffré altéré d'un seul bit",
			counter: harness.MetricDecryptErrors,
			mutate: func(e *harness.Event) {
				e.Tamper = func(ev *bus.EncryptedEvent) {
					ev.Crypto.Ciphertext = flipLastBit(ev.Crypto.Ciphertext)
				}
			},
		},
		{
			name:    "AAD scellée pour un autre tenant",
			counter: harness.MetricDecryptErrors,
			mutate: func(e *harness.Event) {
				e.AAD = &crypto.AADContext{
					TenantID: "tenant-pirate", AppID: e.AppID,
					TopicID: e.TopicID, EventID: e.EventID, Version: e.Version,
				}
			},
		},
		{
			name:    "nonce de payload absent",
			counter: harness.MetricDecryptErrors,
			mutate: func(e *harness.Event) {
				e.Tamper = func(ev *bus.EncryptedEvent) { ev.Crypto.PayloadNonce = "" }
			},
		},
		{
			name:    "enveloppe ML-KEM substituée",
			counter: harness.MetricDecryptErrors,
			mutate: func(e *harness.Event) {
				e.Tamper = func(ev *bus.EncryptedEvent) {
					ev.Crypto.EncapsulatedKey = foreign.Crypto.EncapsulatedKey
					ev.Crypto.WrappedKey = foreign.Crypto.WrappedKey
					ev.Crypto.Nonce = foreign.Crypto.Nonce
				}
			},
		},
		{
			name:    "sujet hors capability",
			counter: harness.MetricEventsNoSubscriber,
			mutate:  func(e *harness.Event) { e.TopicID = "salaries" },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := harness.Event{
				TenantID: tenantID, AppID: appID, TopicID: topicID,
				Type:    "order.created",
				EventID: eventID(t),
				Version: 1,
				Payload: []byte(`{"order_id":"A-1024"}`),
			}
			tc.mutate(&ev)

			before := r.scrape(t)
			r.publish(t, ev)

			if leaked := stream.Silent(silenceWindow); len(leaked) > 0 {
				t.Errorf("trames diffusées alors qu'aucune n'était attendue: %v", leaked)
			}

			after := r.scrape(t)
			if got := after.Delta(before, tc.counter); got != 1 {
				t.Errorf("%s a varié de %.0f, attendu 1", tc.counter, got)
			}
			if got := after.Delta(before, harness.MetricEventsDecrypted); got != 0 {
				t.Errorf("%s a varié de %.0f, attendu 0", harness.MetricEventsDecrypted, got)
			}
		})
	}
}

// assertRealKEMEnvelope confirme que l'enveloppe provient d'un véritable
// ML-KEM-1024 et non d'un moteur simulé : FIPS 203 fixe le chiffré à 1568 octets
// et la clé scellée vaut 32 octets de DEK plus 16 octets d'étiquette GCM.
func assertRealKEMEnvelope(t *testing.T, ev bus.EncryptedEvent) {
	t.Helper()

	const (
		mlkem1024CiphertextBytes = 1568
		wrappedKeyBytes          = 48
	)

	if got := decodedLen(t, ev.Crypto.EncapsulatedKey); got != mlkem1024CiphertextBytes {
		t.Errorf("clé encapsulée de %d octets, %d attendus pour ML-KEM-1024", got, mlkem1024CiphertextBytes)
	}
	if got := decodedLen(t, ev.Crypto.WrappedKey); got != wrappedKeyBytes {
		t.Errorf("clé scellée de %d octets, %d attendus (DEK + étiquette GCM)", got, wrappedKeyBytes)
	}
	if ev.Crypto.Nonce == ev.Crypto.PayloadNonce {
		t.Error("le nonce d'enveloppe et le nonce de payload sont identiques : deux chiffrements sous deux clés distinctes ne doivent jamais partager un nonce")
	}
}

func decodedLen(t *testing.T, encoded string) int {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("champ Base64 invalide: %v", err)
	}
	return len(raw)
}

// flipLastBit inverse un bit du dernier octet du chiffré : l'altération minimale
// que seule l'étiquette d'authentification GCM peut détecter.
func flipLastBit(encoded string) string {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 {
		return encoded
	}
	raw[len(raw)-1] ^= 0x01
	return base64.StdEncoding.EncodeToString(raw)
}

func largePayload(t *testing.T, size int) []byte {
	t.Helper()
	blob := make([]byte, size)
	if _, err := rand.Read(blob); err != nil {
		t.Fatalf("tirage de la charge utile: %v", err)
	}
	return []byte(`{"blob":"` + base64.StdEncoding.EncodeToString(blob) + `"}`)
}

func withTTL(c harness.Capability, ttl time.Duration) harness.Capability {
	c.TTL = ttl
	return c
}

func withTopics(c harness.Capability, topics ...string) harness.Capability {
	c.Topics = topics
	return c
}
