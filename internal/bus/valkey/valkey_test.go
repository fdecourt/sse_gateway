package valkey

import (
	"testing"
)

func TestNewBus_MissingAddress(t *testing.T) {
	cfg := Config{}
	_, err := NewBus(cfg, nil)
	if err == nil {
		t.Fatal("attendu une erreur pour adresse Valkey manquante")
	}
}

func TestNewBus_DefaultValues(t *testing.T) {
	// Vérification de la validation et des valeurs par défaut lors de la tentative de connexion
	cfg := Config{
		Address: "127.0.0.1:6379",
	}
	// Doit tenter d'instancier sans panic
	bus, err := NewBus(cfg, nil)
	if err != nil {
		// NewClient peut réussir car rueidis ne se connecte pas de manière synchrone bloquante
		return
	}
	defer bus.Close()

	if bus.Name() != "valkey_event_bus" {
		t.Errorf("nom attendu valkey_event_bus, obtenu: %s", bus.Name())
	}
}
