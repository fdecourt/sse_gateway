package tests

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sse-gateway/internal/api"
	"sse-gateway/internal/auth"
	"sse-gateway/internal/bus"
	"sse-gateway/internal/bus/memory"
	"sse-gateway/internal/config"
	"sse-gateway/internal/crypto"
	"sse-gateway/internal/crypto/httpclient"
	"sse-gateway/internal/event"
	"sse-gateway/internal/health"
	"sse-gateway/internal/hub"
	"sse-gateway/internal/pipeline"
	"sse-gateway/internal/testutil"
)

// pqcGatewayStub rejoue le contrat binaire V2 du go-pqc-gateway :
// 'P' | 'Q' | 0x02 | suiteID(uint16 BE) | len(encapKey)(uint16 BE) | encapKey | nonce[12] | wrappedKey
// et restitue la DEK en octets bruts sur application/octet-stream.
type pqcGatewayStub struct {
	kek []byte
}

func newPQCGatewayStub(t *testing.T) *pqcGatewayStub {
	t.Helper()
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatalf("génération de la KEK échouée: %v", err)
	}
	return &pqcGatewayStub{kek: kek}
}

func (g *pqcGatewayStub) aead(t *testing.T) cipher.AEAD {
	t.Helper()
	block, err := aes.NewCipher(g.kek)
	if err != nil {
		t.Fatalf("cipher AES: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("GCM: %v", err)
	}
	return gcm
}

// wrapDEK scelle la DEK sous la KEK du gateway et retourne (nonce d'enveloppe, clé enveloppée).
func (g *pqcGatewayStub) wrapDEK(t *testing.T, dek []byte) (nonce, wrapped []byte) {
	t.Helper()
	gcm := g.aead(t)
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("nonce d'enveloppe: %v", err)
	}
	return nonce, gcm.Seal(nil, nonce, dek, nil)
}

func (g *pqcGatewayStub) handler(t *testing.T) http.Handler {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/unwrap-key", func(w http.ResponseWriter, r *http.Request) {
		raw := make([]byte, 0, 4096)
		chunk := make([]byte, 1024)
		for {
			n, err := r.Body.Read(chunk)
			raw = append(raw, chunk[:n]...)
			if err != nil {
				break
			}
		}

		if len(raw) < 7 || raw[0] != 'P' || raw[1] != 'Q' || raw[2] != 0x02 {
			http.Error(w, `{"error":"flux binaire invalide","code":400}`, http.StatusBadRequest)
			return
		}
		keyLen := int(binary.BigEndian.Uint16(raw[5:7]))
		if len(raw) < 7+keyLen+12+16 {
			http.Error(w, `{"error":"flux binaire trop court","code":400}`, http.StatusBadRequest)
			return
		}
		nonce := raw[7+keyLen : 7+keyLen+12]
		wrapped := raw[7+keyLen+12:]

		dek, err := g.aead(t).Open(nil, nonce, wrapped, nil)
		if err != nil {
			http.Error(w, `{"error":"déballage impossible","code":400}`, http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(dek)
	})

	return mux
}

// integrationRig assemble la chaîne complète telle que la câble cmd/server.
type integrationRig struct {
	sseURL     string
	memBus     *memory.Bus
	dispatcher *event.Dispatcher
	router     *event.Router
	cfg        *config.Config
	gateway    *pqcGatewayStub
}

func newIntegrationRig(t *testing.T) *integrationRig {
	t.Helper()

	gw := newPQCGatewayStub(t)
	gwServer := httptest.NewServer(gw.handler(t))

	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("chargement de configuration: %v", err)
	}
	cfg.Auth.Driver = "mock"
	cfg.EventBus.Driver = "memory"
	cfg.Heartbeat.Enabled = false
	cfg.Crypto.AADEnabled = true
	cfg.Crypto.MaxPayloadBytes = 1024 * 1024
	cfg.Crypto.HTTP.BaseURL = gwServer.URL
	cfg.Crypto.HTTP.BinaryMode = true

	unwrapper, err := httpclient.NewClient(cfg.Crypto.HTTP)
	if err != nil {
		t.Fatalf("client crypto: %v", err)
	}

	evRouter, err := event.NewRouter(cfg.Routing.TopicTemplate)
	if err != nil {
		t.Fatalf("routeur d'événements: %v", err)
	}

	sseHub := hub.NewHub(16, cfg.Limits, nil)
	memBus := memory.NewBus(100)
	validator := auth.NewMockValidator()

	proc := pipeline.NewProcessor(unwrapper, sseHub, evRouter, cfg, nil, nil)
	dispatcher := event.NewDispatcher(4, 128, proc.HandleEvent, nil)

	busCtx, busCancel := context.WithCancel(context.Background())
	eventsCh, err := memBus.Subscribe(busCtx, nil)
	if err != nil {
		t.Fatalf("souscription au bus: %v", err)
	}

	// Boucle de consommation identique à celle de cmd/server.
	go func() {
		for {
			select {
			case <-busCtx.Done():
				return
			case ev, ok := <-eventsCh:
				if !ok {
					return
				}
				if !ev.IsSchemaSupported() {
					continue
				}
				routingKey := evRouter.BuildKey(ev.TenantID, ev.AppID, ev.TopicID)
				if !sseHub.HasSubscribers(routingKey) {
					continue
				}
				ev.RoutingKey = routingKey
				dispatcher.Dispatch(ev)
			}
		}
	}()

	checkers := []health.Checker{memBus, unwrapper}
	apiRouter := api.NewRouter(cfg, sseHub, validator, checkers, evRouter, nil, nil)
	sseServer := httptest.NewServer(apiRouter.Handler)

	t.Cleanup(func() {
		sseServer.Close()
		apiRouter.Close()
		busCancel()
		dispatcher.Close()
		_ = memBus.Close()
		sseHub.Close()
		_ = unwrapper.Close()
		gwServer.Close()
	})

	return &integrationRig{
		sseURL:     sseServer.URL,
		memBus:     memBus,
		dispatcher: dispatcher,
		router:     evRouter,
		cfg:        cfg,
		gateway:    gw,
	}
}

// publishEncrypted fabrique un événement conforme au schéma realtime-event-v1 :
// DEK aléatoire, scellée sous la KEK du gateway avec son propre nonce d'enveloppe,
// payload chiffré sous la DEK avec un nonce de payload distinct.
func (r *integrationRig) publishEncrypted(t *testing.T, tenantID, appID, topicID, evType, eventID string, version int64, payload []byte) {
	t.Helper()

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("génération de la DEK: %v", err)
	}
	payloadNonce := make([]byte, 12)
	if _, err := rand.Read(payloadNonce); err != nil {
		t.Fatalf("génération du nonce de payload: %v", err)
	}

	var aad []byte
	if r.cfg.Crypto.AADEnabled {
		aad = crypto.BuildAAD(r.cfg.Crypto.AADTemplate, crypto.AADContext{
			TenantID: tenantID,
			AppID:    appID,
			TopicID:  topicID,
			EventID:  eventID,
			Version:  version,
		})
	}

	ciphertext, err := testutil.EncryptPayload(dek, payloadNonce, payload, aad)
	if err != nil {
		t.Fatalf("chiffrement du payload: %v", err)
	}

	envelopeNonce, wrappedKey := r.gateway.wrapDEK(t, dek)
	encapKey := make([]byte, 1568) // ML-KEM-1024
	if _, err := rand.Read(encapKey); err != nil {
		t.Fatalf("clé encapsulée: %v", err)
	}

	r.memBus.Publish(bus.EncryptedEvent{
		Schema:   bus.SupportedEventSchema,
		EventID:  eventID,
		TenantID: tenantID,
		AppID:    appID,
		TopicID:  topicID,
		Type:     evType,
		Version:  version,
		Crypto: bus.EncryptedPayload{
			Algorithm:       "ML-KEM-1024",
			Version:         "GO-PQC-GATEWAY-V2",
			SuiteID:         3,
			EncapsulatedKey: base64.StdEncoding.EncodeToString(encapKey),
			WrappedKey:      base64.StdEncoding.EncodeToString(wrappedKey),
			Nonce:           base64.StdEncoding.EncodeToString(envelopeNonce),
			PayloadNonce:    base64.StdEncoding.EncodeToString(payloadNonce),
			Ciphertext:      base64.StdEncoding.EncodeToString(ciphertext),
		},
	})
}

// startFrameReader démarre un lecteur unique qui découpe le flux SSE en trames complètes
// (blocs terminés par une ligne vide) et les publie au fil de l'eau.
func startFrameReader(reader *bufio.Reader) <-chan string {
	frames := make(chan string, 8)

	go func() {
		defer close(frames)
		var block strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if strings.TrimSpace(line) == "" && block.Len() > 0 {
				frames <- block.String()
				block.Reset()
			} else if strings.TrimSpace(line) != "" {
				block.WriteString(line)
			}
			if err != nil {
				return
			}
		}
	}()

	return frames
}

// nextFrame retire la prochaine trame du flux ou échoue au bout du délai imparti.
func nextFrame(t *testing.T, frames <-chan string, deadline time.Duration) string {
	t.Helper()
	select {
	case frame, ok := <-frames:
		if !ok {
			t.Fatal("flux SSE clos prématurément")
		}
		return frame
	case <-time.After(deadline):
		t.Fatal("aucune trame reçue dans le délai imparti")
		return ""
	}
}

// TestIntegration_EndToEnd_EncryptedEventReachesSubscriber traverse la chaîne complète :
// handshake authentifié, enregistrement dans le hub, publication chiffrée sur le bus,
// déballage de la DEK auprès du gateway PQC via le transport binaire, déchiffrement
// AES-256-GCM avec AAD, puis livraison de la trame SSE au client abonné.
func TestIntegration_EndToEnd_EncryptedEventReachesSubscriber(t *testing.T) {
	rig := newIntegrationRig(t)

	// Le MockValidator renvoie sa capability par défaut : tenant-default / app-default / topic-1.
	req, err := http.NewRequest(http.MethodGet, rig.sseURL+"/v1/events?ticket=jeton-de-test", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("connexion SSE échouée: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("attendu 200 sur le flux SSE, obtenu %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type SSE attendu, obtenu %q", ct)
	}

	frames := startFrameReader(bufio.NewReader(resp.Body))

	// La trame "connected" est émise après Register : la recevoir atteste que
	// l'abonné est bien inscrit dans le hub, sans recourir à une temporisation.
	connected := nextFrame(t, frames, 5*time.Second)
	if !strings.Contains(connected, "event: connected") {
		t.Fatalf("première trame attendue 'connected', obtenue: %q", connected)
	}

	payload := []byte(`{"order_id":"A-4242","amount":1337.5}`)
	rig.publishEncrypted(t, "tenant-default", "app-default", "topic-1", "order.created", "evt-e2e-1", 7, payload)

	frame := nextFrame(t, frames, 5*time.Second)

	if !strings.Contains(frame, "event: order.created") {
		t.Errorf("type d'événement absent de la trame: %q", frame)
	}
	if !strings.Contains(frame, "id: evt-e2e-1") {
		t.Errorf("identifiant d'événement absent de la trame: %q", frame)
	}

	dataLine := ""
	for _, line := range strings.Split(frame, "\n") {
		if strings.HasPrefix(line, "data: ") {
			dataLine = strings.TrimPrefix(line, "data: ")
			break
		}
	}
	if dataLine == "" {
		t.Fatalf("aucune ligne data dans la trame: %q", frame)
	}

	var decoded struct {
		EventID  string          `json:"event_id"`
		TenantID string          `json:"tenant_id"`
		Type     string          `json:"type"`
		Version  int64           `json:"version"`
		Data     json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal([]byte(dataLine), &decoded); err != nil {
		t.Fatalf("payload SSE non désérialisable (%v): %s", err, dataLine)
	}

	if decoded.EventID != "evt-e2e-1" || decoded.TenantID != "tenant-default" || decoded.Version != 7 {
		t.Errorf("métadonnées d'événement incorrectes: %+v", decoded)
	}
	if string(decoded.Data) != string(payload) {
		t.Errorf("payload déchiffré divergent:\nattendu %s\nobtenu  %s", payload, decoded.Data)
	}
}

// TestIntegration_EndToEnd_NoSubscriberSkipsCrypto vérifie le « principe d'or » de bout en bout :
// sans abonné local, l'événement est abandonné sans solliciter le gateway PQC.
func TestIntegration_EndToEnd_NoSubscriberSkipsCrypto(t *testing.T) {
	rig := newIntegrationRig(t)

	// Aucun client SSE connecté : le topic n'a aucun abonné.
	rig.publishEncrypted(t, "tenant-default", "app-default", "topic-orphelin", "order.created", "evt-orphelin", 1, []byte(`{"x":1}`))
	time.Sleep(200 * time.Millisecond)

	if depth := rig.dispatcher.QueueDepth(); depth != 0 {
		t.Errorf("aucun événement ne doit atteindre les voies sans abonné, profondeur observée: %d", depth)
	}
}
