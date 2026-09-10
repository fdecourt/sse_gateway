// Commande testkeys — amorce les identifiants de la pile de développement.
//
// Elle produit, de façon idempotente, la graine Ed25519 de l'autorité de test,
// le fragment d'environnement consommé par docker-compose.dev.yml, et le lot de
// tickets pré-signés que k6 distribue à ses utilisateurs virtuels (k6 ne sait
// pas signer en EdDSA). Réexécutée, elle conserve la graine existante : les
// tickets déjà émis et la configuration de la passerelle restent valides.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sse-gateway/tests/harness"
)

const (
	gatewayEnvFile = "gateway.env"
	ticketsFile    = "tickets.json"
)

func main() {
	env := harness.LoadEnvironment()

	dir := flag.String("dir", env.KeyDir, "répertoire des identifiants de développement")
	count := flag.Int("tickets", 200, "nombre de tickets pré-signés à émettre pour k6")
	tenant := flag.String("tenant", "tenant-dev", "tenant_id gravé dans les tickets")
	app := flag.String("app", "app-dev", "app_id gravé dans les tickets")
	topic := flag.String("topic", "orders", "sujet autorisé par les tickets")
	ttl := flag.Duration("ttl", 24*time.Hour, "durée de validité des tickets")
	flag.Parse()

	if *count < 1 {
		log.Fatal("le nombre de tickets doit être strictement positif")
	}

	issuer, err := harness.EnsureIssuer(*dir)
	if err != nil {
		log.Fatalf("autorité de test: %v", err)
	}

	publicKey, err := issuer.PublicKeyBase64()
	if err != nil {
		log.Fatalf("clé publique: %v", err)
	}

	envPath := filepath.Join(*dir, gatewayEnvFile)
	envBody := fmt.Sprintf("# Généré par « make dev-keys » — ne pas versionner.\nSSE_AUTH_JWT_PUBLIC_KEY=%s\n", publicKey)
	if err := os.WriteFile(envPath, []byte(envBody), 0o600); err != nil {
		log.Fatalf("écriture de %s: %v", envPath, err)
	}

	tickets := make([]string, 0, *count)
	for i := range *count {
		ticket, err := issuer.Mint(harness.Capability{
			UserID:   fmt.Sprintf("dev-user-%d", i),
			TenantID: *tenant,
			AppID:    *app,
			Topics:   []string{*topic},
			TTL:      *ttl,
		})
		if err != nil {
			log.Fatalf("signature du ticket %d: %v", i, err)
		}
		tickets = append(tickets, ticket)
	}

	encoded, err := json.Marshal(tickets)
	if err != nil {
		log.Fatalf("sérialisation des tickets: %v", err)
	}
	ticketsPath := filepath.Join(*dir, ticketsFile)
	if err := os.WriteFile(ticketsPath, encoded, 0o600); err != nil {
		log.Fatalf("écriture de %s: %v", ticketsPath, err)
	}

	fmt.Printf("graine Ed25519    : %s\n", filepath.Join(*dir, harness.SeedFileName))
	fmt.Printf("environnement     : %s\n", envPath)
	fmt.Printf("tickets pré-signés: %s (%d, valides %s)\n", ticketsPath, *count, *ttl)
	fmt.Printf("\nFlux de test manuel :\n  curl -N \"%s/v1/events?ticket=%s\"\n",
		strings.TrimRight(env.GatewayURL, "/"), tickets[0])
}
