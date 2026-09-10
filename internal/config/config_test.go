package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadConfig_Defaults(t *testing.T) {
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() a échoué: %v", err)
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() a échoué sur les valeurs par défaut: %v", err)
	}

	if cfg.HTTP.ListenPort != 8080 {
		t.Errorf("Attendu port 8080, obtenu %d", cfg.HTTP.ListenPort)
	}
	if cfg.Hub.Shards != 256 {
		t.Errorf("Attendu 256 shards, obtenu %d", cfg.Hub.Shards)
	}
	if cfg.Hub.EventLanes != 64 {
		t.Errorf("Attendu 64 event lanes, obtenu %d", cfg.Hub.EventLanes)
	}
	if cfg.EventBus.Driver != "valkey_pubsub" {
		t.Errorf("Attendu driver valkey_pubsub, obtenu %s", cfg.EventBus.Driver)
	}
	if cfg.Heartbeat.Interval != 20*time.Second {
		t.Errorf("Attendu heartbeat 20s, obtenu %v", cfg.Heartbeat.Interval)
	}
}

func TestLoadConfig_FileResolution(t *testing.T) {
	tempDir := t.TempDir()
	secretFile := filepath.Join(tempDir, "test_valkey_secret.txt")
	if err := os.WriteFile(secretFile, []byte("super_secret_valkey_password\n"), 0600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SSE_EVENT_BUS_VALKEY_PASSWORD_FILE", secretFile)
	t.Setenv("SSE_EVENT_BUS_VALKEY_PASSWORD", "ignored_fallback")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() a échoué: %v", err)
	}

	if cfg.EventBus.Valkey.Password != "super_secret_valkey_password" {
		t.Errorf("Résolution de secret _FILE échouée: obtenu %q", cfg.EventBus.Valkey.Password)
	}
}

func TestConfig_Validate_Errors(t *testing.T) {
	cfg := &Config{}
	cfg.HTTP.ListenPort = -1
	if err := cfg.Validate(); err == nil {
		t.Error("Attendu échec de validation sur port négatif")
	}

	cfg.HTTP.ListenPort = 8080
	cfg.Hub.Shards = 0
	if err := cfg.Validate(); err == nil {
		t.Error("Attendu échec de validation sur shards = 0")
	}
}
