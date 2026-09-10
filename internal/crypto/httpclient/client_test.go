package httpclient_test

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"sse-gateway/internal/crypto"
	"sse-gateway/internal/crypto/httpclient"
)

// fakeGateway rejoue le contrat du PQC gateway : il accepte l'enveloppe en JSON+Base64
// ou au format binaire V2, ouvre la DEK sous une KEK connue, et la restitue.
type fakeGateway struct {
	kek []byte
	// lastSuiteID mémorise la valeur reçue afin de vérifier son typage sur le fil.
	lastSuiteID uint16
	// lastContentType permet d'attester du transport réellement emprunté.
	lastContentType string
}

func newFakeGateway(t *testing.T) *fakeGateway {
	t.Helper()
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatalf("génération KEK échouée: %v", err)
	}
	return &fakeGateway{kek: kek}
}

// wrap scelle la DEK sous la KEK et retourne (nonce, wrappedKey).
func (g *fakeGateway) wrap(t *testing.T, dek []byte) (nonce, wrapped []byte) {
	t.Helper()
	block, err := aes.NewCipher(g.kek)
	if err != nil {
		t.Fatalf("cipher AES: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("GCM: %v", err)
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	return nonce, gcm.Seal(nil, nonce, dek, nil)
}

func (g *fakeGateway) open(nonce, wrapped []byte) ([]byte, error) {
	block, err := aes.NewCipher(g.kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, wrapped, nil)
}

func (g *fakeGateway) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/unwrap-key", func(w http.ResponseWriter, r *http.Request) {
		g.lastContentType = r.Header.Get("Content-Type")

		if r.Header.Get("Content-Type") == "application/octet-stream" {
			g.serveBinary(w, r)
			return
		}
		g.serveJSON(w, r)
	})
	return mux
}

// serveJSON reproduit UnwrapKeyRequest/UnwrapKeyResponse du gateway, suite_id typé uint16.
func (g *fakeGateway) serveJSON(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Algorithm       string `json:"algorithm,omitempty"`
		Version         string `json:"version,omitempty"`
		SuiteID         uint16 `json:"suite_id,omitempty"`
		EncapsulatedKey string `json:"encapsulated_key"`
		Nonce           string `json:"nonce"`
		WrappedKey      string `json:"wrapped_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Exactement le comportement du gateway : un suite_id textuel casse le décodage.
		http.Error(w, `{"error":"paramètres invalides","code":400}`, http.StatusBadRequest)
		return
	}
	g.lastSuiteID = req.SuiteID

	nonce, _ := base64.StdEncoding.DecodeString(req.Nonce)
	wrapped, _ := base64.StdEncoding.DecodeString(req.WrappedKey)
	dek, err := g.open(nonce, wrapped)
	if err != nil {
		http.Error(w, `{"error":"déballage impossible","code":400}`, http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"plaintext_key": base64.StdEncoding.EncodeToString(dek),
		"key_length":    len(dek),
	})
}

// serveBinary reproduit parseBinaryEnvelope : 'P','Q',0x02 | suiteID | keyLen | encapKey | nonce[12] | cipher.
func (g *fakeGateway) serveBinary(w http.ResponseWriter, r *http.Request) {
	raw := make([]byte, 0, 4096)
	buf := make([]byte, 1024)
	for {
		n, err := r.Body.Read(buf)
		raw = append(raw, buf[:n]...)
		if err != nil {
			break
		}
	}

	if len(raw) < 7 || raw[0] != 'P' || raw[1] != 'Q' {
		http.Error(w, `{"error":"flux binaire invalide","code":400}`, http.StatusBadRequest)
		return
	}
	if raw[2] != 0x02 {
		http.Error(w, `{"error":"version binaire non supportée","code":400}`, http.StatusBadRequest)
		return
	}
	g.lastSuiteID = binary.BigEndian.Uint16(raw[3:5])
	keyLen := int(binary.BigEndian.Uint16(raw[5:7]))
	if len(raw) < 7+keyLen+12+16 {
		http.Error(w, `{"error":"flux binaire trop court","code":400}`, http.StatusBadRequest)
		return
	}
	nonce := raw[7+keyLen : 7+keyLen+12]
	wrapped := raw[7+keyLen+12:]

	dek, err := g.open(nonce, wrapped)
	if err != nil {
		http.Error(w, `{"error":"déballage impossible","code":400}`, http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(dek)
}

// buildEnvelope produit une enveloppe cohérente avec la KEK du gateway simulé.
func buildEnvelope(t *testing.T, g *fakeGateway, dek []byte, suiteID uint16) crypto.WrappedKeyEnvelope {
	t.Helper()
	nonce, wrapped := g.wrap(t, dek)
	encapKey := make([]byte, 1568) // taille ML-KEM-1024
	if _, err := rand.Read(encapKey); err != nil {
		t.Fatalf("encapKey: %v", err)
	}
	return crypto.WrappedKeyEnvelope{
		Algorithm:       "ML-KEM-1024",
		Version:         "GO-PQC-GATEWAY-V2",
		SuiteID:         suiteID,
		EncapsulatedKey: base64.StdEncoding.EncodeToString(encapKey),
		Nonce:           base64.StdEncoding.EncodeToString(nonce),
		WrappedKey:      base64.StdEncoding.EncodeToString(wrapped),
	}
}

func TestUnwrap_JSONMode_SuiteIDIsNumeric(t *testing.T) {
	gw := newFakeGateway(t)
	srv := httptest.NewServer(gw.handler())
	defer srv.Close()

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatal(err)
	}

	client, err := httpclient.NewClient(httpclient.ClientConfig{
		BaseURL:    srv.URL,
		BinaryMode: false,
	})
	if err != nil {
		t.Fatalf("création client: %v", err)
	}
	defer func() { _ = client.Close() }()

	got, err := client.Unwrap(context.Background(), buildEnvelope(t, gw, dek, 3))
	if err != nil {
		t.Fatalf("déballage JSON échoué: %v", err)
	}
	if string(got) != string(dek) {
		t.Fatal("DEK restituée différente de la DEK d'origine")
	}
	if gw.lastSuiteID != 3 {
		t.Errorf("suite_id attendu 3 sur le fil, obtenu %d", gw.lastSuiteID)
	}
}

func TestUnwrap_BinaryMode(t *testing.T) {
	gw := newFakeGateway(t)
	srv := httptest.NewServer(gw.handler())
	defer srv.Close()

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatal(err)
	}

	client, err := httpclient.NewClient(httpclient.ClientConfig{
		BaseURL:    srv.URL,
		BinaryMode: true,
	})
	if err != nil {
		t.Fatalf("création client: %v", err)
	}
	defer func() { _ = client.Close() }()

	got, err := client.Unwrap(context.Background(), buildEnvelope(t, gw, dek, 7))
	if err != nil {
		t.Fatalf("déballage binaire échoué: %v", err)
	}
	if string(got) != string(dek) {
		t.Fatal("DEK restituée différente de la DEK d'origine")
	}
	if gw.lastContentType != "application/octet-stream" {
		t.Errorf("transport binaire attendu, Content-Type observé: %q", gw.lastContentType)
	}
	if gw.lastSuiteID != 7 {
		t.Errorf("suite_id attendu 7 dans l'en-tête binaire, obtenu %d", gw.lastSuiteID)
	}
}

func TestUnwrap_BinaryMode_RejectsMalformedNonce(t *testing.T) {
	gw := newFakeGateway(t)
	srv := httptest.NewServer(gw.handler())
	defer srv.Close()

	client, err := httpclient.NewClient(httpclient.ClientConfig{
		BaseURL:    srv.URL,
		BinaryMode: true,
	})
	if err != nil {
		t.Fatalf("création client: %v", err)
	}
	defer func() { _ = client.Close() }()

	env := crypto.WrappedKeyEnvelope{
		EncapsulatedKey: base64.StdEncoding.EncodeToString([]byte("encap")),
		Nonce:           base64.StdEncoding.EncodeToString([]byte("trop-court")), // != 12 octets
		WrappedKey:      base64.StdEncoding.EncodeToString([]byte("wrapped")),
	}

	if _, err := client.Unwrap(context.Background(), env); !errors.Is(err, crypto.ErrInvalidEnvelope) {
		t.Fatalf("attendu crypto.ErrInvalidEnvelope, obtenu: %v", err)
	}
}

func TestUnwrap_UnixSocketTransport(t *testing.T) {
	gw := newFakeGateway(t)

	// Chemin court volontaire : les sockets de domaine Unix sont bornés en longueur
	// (~108 octets sous Linux), ce que t.TempDir() dépasse parfois.
	dir, err := os.MkdirTemp("", "pqsock")
	if err != nil {
		t.Fatalf("répertoire temporaire: %v", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	socketPath := filepath.Join(dir, "pq.sock")

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		// Plateformes sans AF_UNIX : la couverture est assurée ailleurs, on ne bloque pas.
		t.Skipf("socket Unix indisponible sur %s: %v", runtime.GOOS, err)
	}
	srv := &http.Server{Handler: gw.handler()}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		_ = srv.Close()
		_ = os.Remove(socketPath)
	}()

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatal(err)
	}

	client, err := httpclient.NewClient(httpclient.ClientConfig{
		BaseURL:    "unix://" + socketPath,
		BinaryMode: true,
	})
	if err != nil {
		t.Fatalf("création client: %v", err)
	}
	defer func() { _ = client.Close() }()

	got, err := client.Unwrap(context.Background(), buildEnvelope(t, gw, dek, 1))
	if err != nil {
		t.Fatalf("déballage via socket Unix échoué: %v", err)
	}
	if string(got) != string(dek) {
		t.Fatal("DEK restituée différente de la DEK d'origine")
	}

	if err := client.Health(context.Background()); err != nil {
		t.Errorf("sonde de santé via socket Unix échouée: %v", err)
	}
}

func TestNewClient_RejectsEmptyUnixSocketPath(t *testing.T) {
	if _, err := httpclient.NewClient(httpclient.ClientConfig{BaseURL: "unix://"}); err == nil {
		t.Fatal("un chemin de socket Unix vide doit être refusé")
	}
}
