package auth_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"sse-gateway/internal/auth"
)

func generateTestEd25519Key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("échec de génération de la clé Ed25519 de test: %v", err)
	}
	return pub, priv
}

func createTestToken(t *testing.T, privKey ed25519.PrivateKey, claims auth.CustomClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tokenString, err := token.SignedString(privKey)
	if err != nil {
		t.Fatalf("échec de signature du token JWT: %v", err)
	}
	return tokenString
}

func TestJWTValidator_ValidToken(t *testing.T) {
	pub, priv := generateTestEd25519Key(t)

	cfg := auth.JWTConfig{
		Algorithm:      "EdDSA",
		PublicKeyBytes: pub,
		Audience:       "sse-gateway",
		RequireExp:     true,
		RequireAud:     true,
		ClockSkew:      10 * time.Second,
	}

	validator, err := auth.NewJWTValidator(cfg)
	if err != nil {
		t.Fatalf("initialisation du validateur échouée: %v", err)
	}

	claims := auth.CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-alice",
			Audience:  jwt.ClaimStrings{"sse-gateway"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
		},
		TenantID: "tenant-acme",
		AppID:    "app-crm",
		Topics:   []string{"notifications", "chat"},
	}

	token := createTestToken(t, priv, claims)

	cap, err := validator.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("validation attendue avec succès, erreur obtenue: %v", err)
	}

	if cap.UserID != "user-alice" {
		t.Errorf("UserID inattendu: got %s, want user-alice", cap.UserID)
	}
	if cap.TenantID != "tenant-acme" {
		t.Errorf("TenantID inattendu: got %s, want tenant-acme", cap.TenantID)
	}
	if cap.AppID != "app-crm" {
		t.Errorf("AppID inattendu: got %s, want app-crm", cap.AppID)
	}
	if len(cap.Topics) != 2 || cap.Topics[0] != "notifications" {
		t.Errorf("Topics inattendus: %v", cap.Topics)
	}
}

func TestJWTValidator_AlgorithmCaseInsensitive(t *testing.T) {
	pub, priv := generateTestEd25519Key(t)

	// Test avec minuscules 'eddsa'
	cfg := auth.JWTConfig{
		Algorithm:      "eddsa",
		PublicKeyBytes: pub,
		Audience:       "sse-gateway",
		RequireExp:     false,
		RequireAud:     false,
	}

	validator, err := auth.NewJWTValidator(cfg)
	if err != nil {
		t.Fatalf("échec d'initialisation avec eddsa en minuscules: %v", err)
	}

	claims := auth.CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "user-bob",
		},
		TenantID: "tenant-1",
		Topics:   []string{"topic-1"},
	}

	token := createTestToken(t, priv, claims)

	cap, err := validator.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("la validation doit réussir même si Algorithm='eddsa' en minuscules: %v", err)
	}
	if cap.UserID != "user-bob" {
		t.Errorf("attendu user-bob, reçu: %s", cap.UserID)
	}
}

func TestJWTValidator_TamperedSignature(t *testing.T) {
	pub, _ := generateTestEd25519Key(t)
	_, otherPriv := generateTestEd25519Key(t)

	cfg := auth.JWTConfig{
		Algorithm:      "EdDSA",
		PublicKeyBytes: pub,
	}

	validator, err := auth.NewJWTValidator(cfg)
	if err != nil {
		t.Fatal(err)
	}

	claims := auth.CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "user-mallory",
		},
		TenantID: "tenant-hacked",
		Topics:   []string{"root"},
	}

	// Signé avec une clé différente
	token := createTestToken(t, otherPriv, claims)

	_, err = validator.Validate(context.Background(), token)
	if err == nil {
		t.Fatal("un token signé par une mauvaise clé doit être rejeté")
	}
}

func TestJWTValidator_ExpiredToken(t *testing.T) {
	pub, priv := generateTestEd25519Key(t)

	cfg := auth.JWTConfig{
		Algorithm:      "EdDSA",
		PublicKeyBytes: pub,
		RequireExp:     true,
		ClockSkew:      1 * time.Second,
	}

	validator, err := auth.NewJWTValidator(cfg)
	if err != nil {
		t.Fatal(err)
	}

	claims := auth.CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-expired",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute)), // Expiré
		},
		TenantID: "tenant-1",
		Topics:   []string{"topic-1"},
	}

	token := createTestToken(t, priv, claims)

	_, err = validator.Validate(context.Background(), token)
	if err == nil {
		t.Fatal("un token expiré doit être rejeté")
	}
}

func TestJWTValidator_AudienceMismatch(t *testing.T) {
	pub, priv := generateTestEd25519Key(t)

	cfg := auth.JWTConfig{
		Algorithm:      "EdDSA",
		PublicKeyBytes: pub,
		Audience:       "sse-gateway",
		RequireAud:     true,
	}

	validator, err := auth.NewJWTValidator(cfg)
	if err != nil {
		t.Fatal(err)
	}

	claims := auth.CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:  "user-eve",
			Audience: jwt.ClaimStrings{"different-service"}, // Mauvaise audience
		},
		TenantID: "tenant-1",
		Topics:   []string{"topic-1"},
	}

	token := createTestToken(t, priv, claims)

	_, err = validator.Validate(context.Background(), token)
	if err == nil {
		t.Fatal("un token avec une audience non concordante doit être rejeté")
	}
	if !errors.Is(err, auth.ErrInvalidAudience) {
		t.Errorf("attendu auth.ErrInvalidAudience, obtenu: %v", err)
	}
}

func TestJWTValidator_IssuerMismatch(t *testing.T) {
	pub, priv := generateTestEd25519Key(t)

	cfg := auth.JWTConfig{
		Algorithm:      "EdDSA",
		PublicKeyBytes: pub,
		Issuer:         "auth-authority",
		RequireIss:     true,
	}

	validator, err := auth.NewJWTValidator(cfg)
	if err != nil {
		t.Fatal(err)
	}

	claims := auth.CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "user-eve",
			Issuer:  "malicious-issuer",
		},
		TenantID: "tenant-1",
		Topics:   []string{"topic-1"},
	}

	token := createTestToken(t, priv, claims)

	_, err = validator.Validate(context.Background(), token)
	if err == nil {
		t.Fatal("un token avec un émetteur non concordant doit être rejeté")
	}
	if !errors.Is(err, auth.ErrInvalidIssuer) {
		t.Errorf("attendu auth.ErrInvalidIssuer, obtenu: %v", err)
	}
}

func TestJWTValidator_MissingRequiredClaims(t *testing.T) {
	pub, priv := generateTestEd25519Key(t)

	cfg := auth.JWTConfig{
		Algorithm:      "EdDSA",
		PublicKeyBytes: pub,
	}

	validator, _ := auth.NewJWTValidator(cfg)

	// Cas 1: Subject (user_id) manquant
	c1 := auth.CustomClaims{
		TenantID: "t1",
		Topics:   []string{"top"},
	}
	t1 := createTestToken(t, priv, c1)
	if _, err := validator.Validate(context.Background(), t1); err == nil {
		t.Error("doit rejeter si sub manquant")
	} else if !errors.Is(err, auth.ErrMissingClaims) {
		t.Errorf("attendu auth.ErrMissingClaims pour sub manquant, obtenu: %v", err)
	}

	// Cas 2: TenantID manquant
	c2 := auth.CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: "u1"},
		Topics:           []string{"top"},
	}
	t2 := createTestToken(t, priv, c2)
	if _, err := validator.Validate(context.Background(), t2); err == nil {
		t.Error("doit rejeter si tenant_id manquant")
	} else if !errors.Is(err, auth.ErrMissingClaims) {
		t.Errorf("attendu auth.ErrMissingClaims pour tenant_id manquant, obtenu: %v", err)
	}

	// Cas 3: Topics vide
	c3 := auth.CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: "u1"},
		TenantID:         "t1",
		Topics:           []string{},
	}
	t3 := createTestToken(t, priv, c3)
	if _, err := validator.Validate(context.Background(), t3); err == nil {
		t.Error("doit rejeter si topics vide")
	} else if !errors.Is(err, auth.ErrMissingClaims) {
		t.Errorf("attendu auth.ErrMissingClaims pour topics vide, obtenu: %v", err)
	}
}

func TestJWTValidator_EmptyTicket(t *testing.T) {
	pub, _ := generateTestEd25519Key(t)
	cfg := auth.JWTConfig{
		Algorithm:      "EdDSA",
		PublicKeyBytes: pub,
	}
	validator, _ := auth.NewJWTValidator(cfg)

	_, err := validator.Validate(context.Background(), "")
	if !errors.Is(err, auth.ErrMissingTicket) {
		t.Errorf("attendu auth.ErrMissingTicket pour ticket vide, obtenu: %v", err)
	}
}

func TestJWTValidator_Base64PublicKey(t *testing.T) {
	pub, priv := generateTestEd25519Key(t)

	// Format Base64 standard d'une clé brute de 32 octets, tel qu'on le trouve
	// dans une configuration rédigée à la main.
	pubB64Std := []byte(base64.StdEncoding.EncodeToString(pub))
	cfgStd := auth.JWTConfig{
		Algorithm:      "EdDSA",
		PublicKeyBytes: pubB64Std,
		Audience:       "sse-gateway",
	}

	valStd, err := auth.NewJWTValidator(cfgStd)
	if err != nil {
		t.Fatalf("échec d'initialisation avec clé Base64 Standard: %v", err)
	}

	claims := auth.CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:  "user-base64",
			Audience: jwt.ClaimStrings{"sse-gateway"},
		},
		TenantID: "tenant-b64",
		Topics:   []string{"news"},
	}
	token := createTestToken(t, priv, claims)

	cap, err := valStd.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("validation échouée avec clé Base64 Standard: %v", err)
	}
	if cap.UserID != "user-base64" {
		t.Errorf("UserID inattendu: got %s, want user-base64", cap.UserID)
	}

	// Format RawURL Base64
	pubB64URL := []byte(base64.RawURLEncoding.EncodeToString(pub))
	cfgURL := auth.JWTConfig{
		Algorithm:      "EdDSA",
		PublicKeyBytes: pubB64URL,
		Audience:       "sse-gateway",
	}

	valURL, err := auth.NewJWTValidator(cfgURL)
	if err != nil {
		t.Fatalf("échec d'initialisation avec clé Base64 RawURL: %v", err)
	}

	cap2, err := valURL.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("validation échouée avec clé Base64 RawURL: %v", err)
	}
	if cap2.UserID != "user-base64" {
		t.Errorf("UserID inattendu: got %s, want user-base64", cap2.UserID)
	}
}
