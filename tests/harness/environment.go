// Package harness fournit le banc d'essai partagé par les tests de bout en bout,
// le générateur de trafic chiffré et l'émetteur d'identifiants de développement.
//
// Il vit dans le module de la passerelle et réutilise ses types de production —
// bus.EncryptedEvent, auth.CustomClaims, crypto.BuildAAD, testutil.EncryptPayload.
// Toute évolution du schéma d'événement ou des revendications casse donc la
// compilation du banc d'essai, et non une exécution six mois plus tard.
package harness

import (
	"os"
	"path/filepath"
	"strings"
)

// Valeurs par défaut de la pile de développement décrite par docker-compose.dev.yml.
// Les ports sont décalés afin qu'un `make run` local puisse occuper 8080 pendant
// que la pile conteneurisée tourne en parallèle.
const (
	DefaultGatewayURL = "http://127.0.0.1:18080"
	DefaultCryptoURL  = "http://127.0.0.1:18085"
	DefaultValkeyAddr = "127.0.0.1:16379"
	DefaultChannel    = "realtime.e2e"
	DefaultKeyDir     = ".dev"
)

// Environment localise les composants de la pile de test.
type Environment struct {
	GatewayURL string // passerelle SSE (flux, sondes, /metrics)
	CryptoURL  string // microservice post-quantique (encapsulation ML-KEM)
	ValkeyAddr string // bus d'événements Pub/Sub
	Channel    string // canal de publication, doit satisfaire le motif souscrit
	KeyDir     string // répertoire des identifiants de développement
}

// LoadEnvironment lit la configuration du banc d'essai depuis l'environnement,
// en repliant sur la pile de développement standard.
func LoadEnvironment() Environment {
	return Environment{
		GatewayURL: getEnv("SSE_E2E_GATEWAY_URL", DefaultGatewayURL),
		CryptoURL:  getEnv("SSE_E2E_CRYPTO_URL", DefaultCryptoURL),
		ValkeyAddr: getEnv("SSE_E2E_VALKEY_ADDR", DefaultValkeyAddr),
		Channel:    getEnv("SSE_E2E_CHANNEL", DefaultChannel),
		KeyDir:     getEnv("SSE_E2E_KEY_DIR", defaultKeyDir()),
	}
}

func getEnv(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}

// defaultKeyDir ancre le répertoire d'identifiants sur la racine du module.
//
// Les outils s'exécutent depuis la racine du dépôt, `go test` depuis le
// répertoire du paquet testé : un chemin relatif nu désignerait deux endroits
// différents, et le banc d'essai signerait avec une clé que la passerelle ne
// connaît pas. Le repli sur le chemin relatif ne sert que le cas dégradé où le
// répertoire courant est introuvable.
func defaultKeyDir() string {
	dir, err := os.Getwd()
	if err != nil {
		return DefaultKeyDir
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, DefaultKeyDir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return DefaultKeyDir
		}
		dir = parent
	}
}
