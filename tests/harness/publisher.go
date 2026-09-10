package harness

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/valkey-io/valkey-go"
	"sse-gateway/internal/bus"
	"sse-gateway/internal/crypto"
	"sse-gateway/internal/testutil"
)

// gcmNonceSize est la taille de nonce imposée par AES-GCM en mode standard.
const gcmNonceSize = 12

// dataKey est la réponse de POST /generate-key du microservice post-quantique :
// la clé de données en clair pour le producteur, et la même clé scellée sous
// ML-KEM pour la passerelle. C'est un contrat inter-services, donc le seul
// endroit du banc d'essai où une structure doit être redéclarée.
type dataKey struct {
	Algorithm       string `json:"algorithm"`
	Version         string `json:"version"`
	SuiteID         uint16 `json:"suite_id"`
	PlaintextKey    string `json:"plaintext_key"`
	EncapsulatedKey string `json:"encapsulated_key"`
	Nonce           string `json:"nonce"`
	WrappedKey      string `json:"wrapped_key"`
}

// Event décrit l'intention de publication en clair. Le chiffrement, l'AAD et
// l'enveloppe ML-KEM sont dérivés par le Publisher.
type Event struct {
	TenantID string
	AppID    string
	TopicID  string
	Type     string
	EventID  string
	Version  int64
	Payload  []byte

	// AAD force le contexte d'authentification additionnelle. Laissé à nil, il
	// est déduit des métadonnées ci-dessus — donc cohérent. Le renseigner permet
	// de sceller un chiffré valide pour un contexte de routage différent.
	AAD *crypto.AADContext

	// Tamper alter l'événement juste avant sérialisation. Point d'extension
	// unique des scénarios négatifs : altération de chiffré, retrait de nonce,
	// substitution d'enveloppe.
	Tamper func(*bus.EncryptedEvent)
}

// Publisher produit de véritables événements chiffrés et les pousse sur le bus.
// Il tient le rôle du service métier amont : il obtient une clé de données
// scellée auprès du microservice post-quantique, chiffre la charge utile
// localement en AES-256-GCM, et n'a jamais accès à la clé privée ML-KEM.
type Publisher struct {
	cryptoURL string
	channel   string
	client    valkey.Client
	http      *http.Client
}

// NewPublisher ouvre la connexion au bus d'événements.
func NewPublisher(env Environment) (*Publisher, error) {
	client, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{env.ValkeyAddr}})
	if err != nil {
		return nil, fmt.Errorf("connexion au bus %s: %w", env.ValkeyAddr, err)
	}
	return &Publisher{
		cryptoURL: strings.TrimRight(env.CryptoURL, "/"),
		channel:   env.Channel,
		client:    client,
		http:      &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// Close libère la connexion au bus.
func (p *Publisher) Close() { p.client.Close() }

// Publish chiffre l'événement de bout en bout et le publie. L'événement rendu
// est celui effectivement sérialisé, altérations comprises, ce qui permet aux
// tests d'affirmer sur son contenu exact.
func (p *Publisher) Publish(ctx context.Context, ev Event) (bus.EncryptedEvent, error) {
	encrypted, err := p.Seal(ctx, ev)
	if err != nil {
		return encrypted, err
	}

	raw, err := json.Marshal(encrypted)
	if err != nil {
		return encrypted, fmt.Errorf("sérialisation de l'événement: %w", err)
	}
	cmd := p.client.B().Publish().Channel(p.channel).Message(string(raw)).Build()
	if err := p.client.Do(ctx, cmd).Error(); err != nil {
		return encrypted, fmt.Errorf("publication sur %s: %w", p.channel, err)
	}
	return encrypted, nil
}

// Seal construit l'événement chiffré sans le publier.
func (p *Publisher) Seal(ctx context.Context, ev Event) (bus.EncryptedEvent, error) {
	var out bus.EncryptedEvent

	dk, dek, err := p.generateDataKey(ctx)
	if err != nil {
		return out, err
	}
	defer crypto.Zeroize(dek)

	aadCtx := crypto.AADContext{
		TenantID: ev.TenantID,
		AppID:    ev.AppID,
		TopicID:  ev.TopicID,
		EventID:  ev.EventID,
		Version:  ev.Version,
	}
	if ev.AAD != nil {
		aadCtx = *ev.AAD
	}

	// Le nonce du payload est distinct de celui de l'enveloppe : deux
	// chiffrements sous deux clés différentes ne partagent jamais un nonce.
	payloadNonce := make([]byte, gcmNonceSize)
	if _, err := rand.Read(payloadNonce); err != nil {
		return out, fmt.Errorf("tirage du nonce de payload: %w", err)
	}

	ciphertext, err := testutil.EncryptPayload(dek, payloadNonce, ev.Payload,
		crypto.BuildAAD(crypto.DefaultAADTemplate, aadCtx))
	if err != nil {
		return out, fmt.Errorf("chiffrement AES-256-GCM de la charge utile: %w", err)
	}

	out = bus.EncryptedEvent{
		Schema:    bus.SupportedEventSchema,
		EventID:   ev.EventID,
		TenantID:  ev.TenantID,
		AppID:     ev.AppID,
		TopicID:   ev.TopicID,
		Type:      ev.Type,
		Version:   ev.Version,
		CreatedAt: time.Now().UTC(),
		Crypto: bus.EncryptedPayload{
			Algorithm:       dk.Algorithm,
			Version:         dk.Version,
			SuiteID:         dk.SuiteID,
			EncapsulatedKey: dk.EncapsulatedKey,
			WrappedKey:      dk.WrappedKey,
			Nonce:           dk.Nonce,
			PayloadNonce:    base64.StdEncoding.EncodeToString(payloadNonce),
			Ciphertext:      base64.StdEncoding.EncodeToString(ciphertext),
		},
	}
	if ev.Tamper != nil {
		ev.Tamper(&out)
	}
	return out, nil
}

// generateDataKey sollicite une encapsulation ML-KEM réelle auprès du
// microservice cryptographique et rend la clé de données en clair.
func (p *Publisher) generateDataKey(ctx context.Context) (dataKey, []byte, error) {
	var dk dataKey

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.cryptoURL+"/generate-key", bytes.NewReader([]byte(`{"key_length":32}`)))
	if err != nil {
		return dk, nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.http.Do(req)
	if err != nil {
		return dk, nil, fmt.Errorf("appel à %s/generate-key: %w", p.cryptoURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return dk, nil, fmt.Errorf("lecture de la réponse /generate-key: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return dk, nil, fmt.Errorf("/generate-key a répondu %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, &dk); err != nil {
		return dk, nil, fmt.Errorf("réponse /generate-key illisible: %w", err)
	}

	dek, err := base64.StdEncoding.DecodeString(dk.PlaintextKey)
	if err != nil {
		return dk, nil, fmt.Errorf("clé de données Base64 invalide: %w", err)
	}
	if len(dek) != 32 {
		return dk, nil, fmt.Errorf("clé de données de %d octets, 32 attendus pour AES-256", len(dek))
	}
	return dk, dek, nil
}
