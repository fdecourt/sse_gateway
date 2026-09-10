package event_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sse-gateway/internal/bus"
	"sse-gateway/internal/event"
)

func TestDispatcher_DispatchAndDrain(t *testing.T) {
	var processedCount atomic.Int64
	var wg sync.WaitGroup

	totalEvents := 100
	wg.Add(totalEvents)

	handler := func(ctx context.Context, ev bus.EncryptedEvent) {
		processedCount.Add(1)
		wg.Done()
	}

	dispatcher := event.NewDispatcher(8, 256, handler, nil)

	for i := 0; i < totalEvents; i++ {
		ev := bus.EncryptedEvent{
			EventID:  "ev-test",
			TenantID: "tenant-1",
			AppID:    "app-1",
			TopicID:  "topic-orders",
		}
		if !dispatcher.Dispatch(ev) {
			t.Fatalf("échec d'acheminement de l'événement %d", i)
		}
	}

	// Attente du traitement des événements
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout: seuls %d événements sur %d ont été traités", processedCount.Load(), totalEvents)
	}

	// Clôture propre
	dispatcher.Close()

	if processedCount.Load() != int64(totalEvents) {
		t.Errorf("attendu %d événements traités, obtenu %d", totalEvents, processedCount.Load())
	}
}

// TestDispatcher_DrainWithActiveContext vérifie qu'à l'arrêt, les événements drainés
// sont traités avec un contexte encore valide (non annulé) pour que les appels HTTP/crypto réussissent.
func TestDispatcher_DrainWithActiveContext(t *testing.T) {
	var processedCount atomic.Int64
	var contextCanceledErrors atomic.Int64

	handler := func(ctx context.Context, ev bus.EncryptedEvent) {
		time.Sleep(5 * time.Millisecond)
		if ctx.Err() != nil {
			contextCanceledErrors.Add(1)
		}
		processedCount.Add(1)
	}

	dispatcher := event.NewDispatcher(4, 32, handler, nil)

	// Envoyer 16 événements
	for i := 0; i < 16; i++ {
		dispatcher.Dispatch(bus.EncryptedEvent{
			TenantID: "tenant-1",
			AppID:    "app-1",
			TopicID:  "topic-drain",
		})
	}

	// Lancer immédiatement la fermeture pendant que les événements sont encore en file
	dispatcher.Close()

	if processedCount.Load() != 16 {
		t.Fatalf("tous les événements n'ont pas été drainés: %d/16", processedCount.Load())
	}
	if contextCanceledErrors.Load() != 0 {
		t.Fatalf("le contexte était annulé pendant le drainage pour %d événements", contextCanceledErrors.Load())
	}
}

func TestDispatcher_ShutdownNoPanic(t *testing.T) {
	dispatcher := event.NewDispatcher(4, 32, func(ctx context.Context, ev bus.EncryptedEvent) {}, nil)

	var wg sync.WaitGroup
	// Concurrence : dispatchs intensifs pendant la fermeture
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				dispatcher.Dispatch(bus.EncryptedEvent{
					TenantID: "t",
					AppID:    "a",
					TopicID:  "top",
				})
			}
		}()
	}

	// Fermeture concurrente : ne doit JAMAIS provoquer de panique sur canal fermé
	time.Sleep(1 * time.Millisecond)
	dispatcher.Close()
	wg.Wait()
}

// TestDispatcher_DrainTimeoutForcesExit vérifie qu'un handler bloqué n'empêche pas Close() de retourner
// grâce à l'échéance forcée par SetDrainTimeout.
func TestDispatcher_DrainTimeoutForcesExit(t *testing.T) {
	// Handler qui bloque indéfiniment
	handler := func(ctx context.Context, ev bus.EncryptedEvent) {
		<-ctx.Done() // Attend l'annulation forcée du contexte
	}

	dispatcher := event.NewDispatcher(2, 10, handler, nil)
	dispatcher.SetDrainTimeout(50 * time.Millisecond) // Échéance courte de 50ms

	dispatcher.Dispatch(bus.EncryptedEvent{
		TenantID: "t",
		AppID:    "a",
		TopicID:  "stuck",
	})

	start := time.Now()
	dispatcher.Close()
	elapsed := time.Since(start)

	// Close() doit retourner en ~50ms sans bloquer indéfiniment
	if elapsed > 1*time.Second {
		t.Fatalf("Close() a mis trop de temps (%v), le timeout de drain n'a pas fonctionné", elapsed)
	}
}
