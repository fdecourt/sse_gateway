package event_test

import (
	"testing"

	"sse-gateway/internal/event"
)

func TestRouter_BuildAndParseKey(t *testing.T) {
	router, err := event.NewRouter("tenant:{tenant}:app:{app}:topic:{topic}")
	if err != nil {
		t.Fatalf("échec NewRouter: %v", err)
	}

	key := router.BuildKey("tenant-alpha", "app-portal", "events.orders")
	expected := "tenant:tenant-alpha:app:app-portal:topic:events.orders"
	if key != expected {
		t.Errorf("clé générée incorrecte: got %s, want %s", key, expected)
	}

	tenantID, appID, topicID, ok := router.ParseKey(key)
	if !ok {
		t.Fatal("ParseKey attendu avec succès")
	}

	if tenantID != "tenant-alpha" || appID != "app-portal" || topicID != "events.orders" {
		t.Errorf("champs extraits non conformes: %s / %s / %s", tenantID, appID, topicID)
	}
}

func TestRouter_ColonSanitizationPreventsInjection(t *testing.T) {
	router, _ := event.NewRouter("tenant:{tenant}:app:{app}:topic:{topic}")

	// Tentative d'injection de colon dans tenantID
	key := router.BuildKey("evil:tenant:app:injected", "legit-app", "topic-1")

	tenantID, appID, topicID, ok := router.ParseKey(key)
	if !ok {
		t.Fatal("ParseKey doit réussir sur la clé assainie")
	}

	// Le tenant ne doit pas avoir collisionné avec un autre tenant
	if tenantID == "evil" {
		t.Errorf("injection réussie (vulnérable aux collisions): tenantID=%s", tenantID)
	}

	if tenantID != "evil_tenant_app_injected" {
		t.Errorf("assainissement non conforme: got %s", tenantID)
	}
	if appID != "legit-app" || topicID != "topic-1" {
		t.Errorf("champs app ou topic corrompus: %s, %s", appID, topicID)
	}
}
