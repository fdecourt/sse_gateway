package tests

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"sse-gateway/internal/crypto"
)

func TestCrypto_AES_GCM_AAD_Success(t *testing.T) {
	// Génération d'une clé DEK aléatoire de 32 octets (AES-256)
	dek := make([]byte, 32)
	_, _ = rand.Read(dek)

	nonce := make([]byte, 12)
	_, _ = rand.Read(nonce)

	plaintext := []byte(`{"message":"Hello SSE World","status":"secure"}`)

	aadCtx := crypto.AADContext{
		TenantID: "tenant-1",
		AppID:    "app-crm",
		TopicID:  "deals",
		EventID:  "ev-001",
		Version:  42,
	}
	template := "{tenant_id}|{app_id}|{topic_id}|{event_id}|{version}"
	aad := crypto.BuildAAD(template, aadCtx)

	block, err := aes.NewCipher(dek)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)

	nonceB64 := base64.StdEncoding.EncodeToString(nonce)
	ciphertextB64 := base64.StdEncoding.EncodeToString(ciphertext)

	// Déchiffrement avec la fonction du module crypto
	decrypted, err := crypto.DecryptPayload(dek, nonceB64, ciphertextB64, aad, 1024*1024)
	if err != nil {
		t.Fatalf("DecryptPayload a échoué: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Plaintext altéré: attendu %s, obtenu %s", plaintext, decrypted)
	}
}

func TestCrypto_AES_GCM_AAD_TamperRejection(t *testing.T) {
	dek := make([]byte, 32)
	_, _ = rand.Read(dek)
	nonce := make([]byte, 12)
	_, _ = rand.Read(nonce)

	plaintext := []byte("secret payload")
	aadValid := crypto.BuildAAD("{tenant_id}|{topic_id}", crypto.AADContext{
		TenantID: "tenant-1",
		TopicID:  "topic-a",
	})
	aadTampered := crypto.BuildAAD("{tenant_id}|{topic_id}", crypto.AADContext{
		TenantID: "tenant-attacker",
		TopicID:  "topic-a",
	})

	block, _ := aes.NewCipher(dek)
	gcm, _ := cipher.NewGCM(block)
	ciphertext := gcm.Seal(nil, nonce, plaintext, aadValid)

	nonceB64 := base64.StdEncoding.EncodeToString(nonce)
	ciphertextB64 := base64.StdEncoding.EncodeToString(ciphertext)

	// Déchiffrement avec AAD altéré (doit échouer)
	_, err := crypto.DecryptPayload(dek, nonceB64, ciphertextB64, aadTampered, 1024)
	if err == nil {
		t.Fatal("Le déchiffrement avec AAD altéré aurait dû être rejeté !")
	}
}

func TestCrypto_Zeroize(t *testing.T) {
	secret := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x42}
	crypto.Zeroize(secret)

	for i, b := range secret {
		if b != 0 {
			t.Errorf("Octet %d non effacé: 0x%X", i, b)
		}
	}
}
