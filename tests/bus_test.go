package tests

import (
	"context"
	"testing"
	"time"

	"sse-gateway/internal/bus"
	"sse-gateway/internal/bus/memory"
)

func TestBus_Memory_PublishSubscribe(t *testing.T) {
	b := memory.NewBus(10)
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	subCh, err := b.Subscribe(ctx, []string{"realtime.*"})
	if err != nil {
		t.Fatalf("Subscribe a échoué: %v", err)
	}

	event := bus.EncryptedEvent{
		EventID:  "ev-100",
		TenantID: "tenant-a",
		AppID:    "crm",
		TopicID:  "leads",
		Type:     "lead.created",
	}

	b.Publish(event)

	select {
	case received, ok := <-subCh:
		if !ok {
			t.Fatal("Canal fermé inopinément")
		}
		if received.EventID != "ev-100" || received.Type != "lead.created" {
			t.Errorf("Événement corrompu: %+v", received)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Délai d'attente dépassé pour la réception de l'événement")
	}
}

func TestBus_SchemaValidation(t *testing.T) {
	evValid1 := bus.EncryptedEvent{Schema: ""}
	evValid2 := bus.EncryptedEvent{Schema: bus.SupportedEventSchema}
	evInvalid := bus.EncryptedEvent{Schema: "realtime-event-v2-incompatible"}

	if !evValid1.IsSchemaSupported() {
		t.Errorf("Le schéma vide doit être accepté par défaut pour rétro-compatibilité")
	}
	if !evValid2.IsSchemaSupported() {
		t.Errorf("Le schéma %s doit être accepté", bus.SupportedEventSchema)
	}
	if evInvalid.IsSchemaSupported() {
		t.Errorf("Le schéma incompatible %s ne doit pas être accepté", evInvalid.Schema)
	}
}
