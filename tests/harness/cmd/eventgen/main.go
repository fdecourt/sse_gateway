// Commande eventgen — injecte du trafic réellement chiffré dans la passerelle.
//
// Elle complète k6, qui porte la charge côté client (connexions persistantes)
// mais ne sait ni encapsuler en ML-KEM ni publier sur Valkey. Chaque événement
// produit ici suit le chemin de production complet : clé de données scellée par
// le microservice post-quantique, charge utile chiffrée en AES-256-GCM sous AAD,
// publication Pub/Sub. Le rapport final confronte ce qui a été injecté à ce que
// la passerelle a réellement absorbé, relevé sur son exposition Prometheus.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sse-gateway/tests/harness"
)

// drainDelay laisse la passerelle absorber la file d'événements avant le relevé final.
const drainDelay = 3 * time.Second

func main() {
	events := flag.Int("events", 1000, "nombre d'événements chiffrés à publier")
	workers := flag.Int("workers", 32, "producteurs concurrents")
	size := flag.Int("size", 512, "taille de la charge utile applicative, en octets")
	subscribe := flag.Bool("subscribe", true, "ouvrir un abonné, sans lequel la passerelle ne déchiffre rien")
	flag.Parse()

	if *events < 1 || *workers < 1 {
		log.Fatal("le nombre d'événements et de producteurs doit être strictement positif")
	}

	env := harness.LoadEnvironment()
	ctx := context.Background()

	publisher, err := harness.NewPublisher(env)
	if err != nil {
		log.Fatalf("producteur: %v", err)
	}
	defer publisher.Close()

	capability := harness.Capability{
		UserID:   "eventgen-observer",
		TenantID: "tenant-dev",
		AppID:    "app-dev",
		Topics:   []string{"orders"},
		TTL:      time.Hour,
	}

	if *subscribe {
		stream, err := openObserver(env, capability)
		if err != nil {
			log.Fatalf("abonné d'observation: %v", err)
		}
		defer stream.Close()
	}

	before, err := harness.Scrape(env.GatewayURL)
	if err != nil {
		log.Fatalf("relevé initial: %v", err)
	}

	payload := []byte(`{"blob":"` + strings.Repeat("x", *size) + `"}`)
	published, rejected, elapsed := inject(ctx, publisher, capability, payload, *events, *workers)

	time.Sleep(drainDelay)
	after, err := harness.Scrape(env.GatewayURL)
	if err != nil {
		log.Fatalf("relevé final: %v", err)
	}

	report(published, rejected, elapsed, before, after)
}

// inject publie les événements en parallèle et rend le nombre de succès, le
// nombre d'échecs et la durée de la phase d'injection.
func inject(ctx context.Context, publisher *harness.Publisher, capability harness.Capability,
	payload []byte, events, workers int) (published, rejected int64, elapsed time.Duration) {

	var ok, ko atomic.Int64
	jobs := make(chan int, workers*2)
	var wg sync.WaitGroup

	start := time.Now()
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				_, err := publisher.Publish(ctx, harness.Event{
					TenantID: capability.TenantID,
					AppID:    capability.AppID,
					TopicID:  capability.Topics[0],
					Type:     "load.event",
					EventID:  fmt.Sprintf("eventgen-%d", i),
					Version:  int64(i),
					Payload:  payload,
				})
				if err != nil {
					ko.Add(1)
					continue
				}
				ok.Add(1)
			}
		}()
	}
	for i := range events {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	return ok.Load(), ko.Load(), time.Since(start)
}

// openObserver ouvre un abonné dont la file est vidée en continu : sans lecteur
// assidu, la passerelle le classerait client lent et le déconnecterait.
func openObserver(env harness.Environment, capability harness.Capability) (*harness.Stream, error) {
	issuer, err := harness.NewIssuer(env.KeyDir)
	if err != nil {
		return nil, err
	}
	ticket, err := issuer.Mint(capability)
	if err != nil {
		return nil, err
	}
	stream, err := harness.Open(env.GatewayURL, ticket, 4096)
	if err != nil {
		return nil, err
	}
	go func() {
		for range stream.Frames() {
		}
	}()
	return stream, nil
}

// report confronte le trafic injecté à ce que la passerelle a absorbé.
func report(published, rejected int64, elapsed time.Duration, before, after harness.Snapshot) {
	fmt.Printf("\n--- Injection de trafic chiffré ---\n")
	fmt.Printf("publiés              : %d (échecs producteur : %d)\n", published, rejected)
	fmt.Printf("durée d'injection    : %s (%.0f évén./s, encapsulation ML-KEM comprise)\n",
		elapsed.Round(time.Millisecond), float64(published)/elapsed.Seconds())
	fmt.Printf("déchiffrés           : %.0f\n", after.Delta(before, harness.MetricEventsDecrypted))
	fmt.Printf("rejets cryptographiques : %.0f\n", after.Delta(before, harness.MetricDecryptErrors))
	fmt.Printf("sans abonné          : %.0f\n", after.Delta(before, harness.MetricEventsNoSubscriber))
	fmt.Printf("trames diffusées     : %.0f\n", after.Delta(before, harness.MetricFanoutRecipients))
	fmt.Printf("clients lents coupés : %.0f\n", after.Delta(before, harness.MetricSlowClients))
	fmt.Printf("déballage + déchiffrement : %.3f ms en moyenne\n",
		after.MeanMillis(before, harness.MetricCryptoDuration))
	fmt.Printf("traitement complet        : %.3f ms en moyenne\n",
		after.MeanMillis(before, harness.MetricProcessingDuration))
}
