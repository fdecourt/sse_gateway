package tlsconf_test

import (
	"crypto/tls"
	"testing"

	"sse-gateway/internal/tlsconf"
)

func TestBuild_Defaults(t *testing.T) {
	cfg, err := tlsconf.Build(tlsconf.Params{
		InsecureSkipVerify: true,
		ServerName:         "localhost",
	})
	if err != nil {
		t.Fatalf("Build attendu avec succès: %v", err)
	}

	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion attendu TLS 1.3, obtenu: %x", cfg.MinVersion)
	}
	if !cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify attendu true")
	}
	if cfg.ServerName != "localhost" {
		t.Errorf("ServerName attendu localhost, obtenu: %s", cfg.ServerName)
	}
}

func TestBuild_InvalidCA(t *testing.T) {
	_, err := tlsconf.Build(tlsconf.Params{
		CAFile: "non-existent-ca-file.crt",
	})
	if err == nil {
		t.Fatal("doit retourner une erreur pour un fichier CA inexistant")
	}
}
