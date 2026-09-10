package tests

import (
	"sync/atomic"
	"testing"

	"sse-gateway/internal/hub"
)

func TestHub_RegisterAndUnregister(t *testing.T) {
	h := hub.NewHub(32, hub.LimitsConfig{}, nil)
	client := hub.NewClient("c1", "user1", "tenant1", []string{"rKey1"}, 10, hub.SlowPolicyDisconnect, nil)

	if err := h.Register(client, []string{"rKey1"}); err != nil {
		t.Fatalf("Register a échoué: %v", err)
	}

	if !h.HasSubscribers("rKey1") {
		t.Error("Attendu HasSubscribers = true")
	}
	if h.ActiveConnections() != 1 {
		t.Errorf("Attendu 1 connexion active, obtenu %d", h.ActiveConnections())
	}

	h.Unregister(client)

	if h.HasSubscribers("rKey1") {
		t.Error("Attendu HasSubscribers = false après unregister")
	}
	if h.ActiveConnections() != 0 {
		t.Errorf("Attendu 0 connexion active, obtenu %d", h.ActiveConnections())
	}
}

func TestHub_ConditionalBroadcast_ZeroSubscriber(t *testing.T) {
	h := hub.NewHub(32, hub.LimitsConfig{}, nil)

	called := false
	decryptFn := func() (*hub.Frame, error) {
		called = true
		return hub.NewDataFrame("test", "1", []byte("data")), nil
	}

	// Diffusion vers un topic sans aucun abonné
	delivered, err := h.ConditionalBroadcast("topic:empty", decryptFn)
	if err != nil {
		t.Fatal(err)
	}

	if delivered != 0 {
		t.Errorf("Attendu 0 messages livrés, obtenu %d", delivered)
	}
	if called {
		t.Fatal("La fonction crypto ne doit JAMAIS être appelée s'il n'y a aucun abonné (règle d'or violée) !")
	}
}

func TestHub_ConditionalBroadcast_Fanout(t *testing.T) {
	h := hub.NewHub(32, hub.LimitsConfig{}, nil)

	const numClients = 10
	clients := make([]*hub.Client, numClients)
	for i := 0; i < numClients; i++ {
		clients[i] = hub.NewClient(string(rune('A'+i)), "user", "tenant", []string{"rKeyShared"}, 10, hub.SlowPolicyDisconnect, nil)
		_ = h.Register(clients[i], []string{"rKeyShared"})
	}

	var callCount atomic.Int32
	frameToShare := hub.NewDataFrame("update", "42", []byte(`{"version":1}`))

	decryptFn := func() (*hub.Frame, error) {
		callCount.Add(1)
		return frameToShare, nil
	}

	delivered, err := h.ConditionalBroadcast("rKeyShared", decryptFn)
	if err != nil {
		t.Fatal(err)
	}

	if delivered != numClients {
		t.Errorf("Attendu %d livraisons, obtenu %d", numClients, delivered)
	}
	if callCount.Load() != 1 {
		t.Errorf("Le déchiffrement doit être exécuté UNE SEULE FOIS pour tous les clients ! Appels: %d", callCount.Load())
	}

	// Vérification de la réception sur tous les clients et partage de pointeur
	for i, c := range clients {
		select {
		case received := <-c.Send:
			if received != frameToShare {
				t.Errorf("Client %d a reçu une copie différente au lieu du pointeur partagé", i)
			}
		default:
			t.Errorf("Client %d n'a rien reçu", i)
		}
	}
}

func TestHub_SlowClient_Isolation(t *testing.T) {
	h := hub.NewHub(32, hub.LimitsConfig{}, nil)

	var slowDetected atomic.Bool
	onSlow := func(c *hub.Client) {
		slowDetected.Store(true)
	}

	// Client lent avec petite queue de 1 trame
	slowClient := hub.NewClient("slow1", "u1", "t1", []string{"topicX"}, 1, hub.SlowPolicyDisconnect, onSlow)
	// Client rapide avec queue suffisante
	fastClient := hub.NewClient("fast1", "u2", "t1", []string{"topicX"}, 10, hub.SlowPolicyDisconnect, nil)

	_ = h.Register(slowClient, []string{"topicX"})
	_ = h.Register(fastClient, []string{"topicX"})

	frame1 := hub.NewDataFrame("msg", "1", []byte("f1"))
	frame2 := hub.NewDataFrame("msg", "2", []byte("f2"))

	// Premier envoi : remplit la queue du client lent
	_, _ = h.ConditionalBroadcast("topicX", func() (*hub.Frame, error) { return frame1, nil })

	// Second envoi : le client lent doit déborder et être déconnecté sans bloquer le rapide
	_, _ = h.ConditionalBroadcast("topicX", func() (*hub.Frame, error) { return frame2, nil })

	if !slowClient.IsClosed() {
		t.Error("Le client lent aurait dû être déconnecté")
	}
	if fastClient.IsClosed() {
		t.Error("Le client rapide ne doit PAS être déconnecté")
	}
	if !slowDetected.Load() {
		t.Error("Le callback onSlow aurait dû être invoqué")
	}
}
