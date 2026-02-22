package jwt

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if key == nil || key.N == nil {
		t.Error("GenerateKey: key is nil or invalid")
	}
	if key.N.BitLen() < 2048 {
		t.Errorf("GenerateKey: key size %d < 2048", key.N.BitLen())
	}
}

func TestSignAndVerify(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer := NewSigner(key)

	sub := uuid.New()
	sid := uuid.New()
	aud := uuid.New()
	jti := "test-jti"

	tokenStr, err := signer.Sign(sub, sid, aud, 1, jti, time.Hour)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if tokenStr == "" {
		t.Error("Sign: empty token")
	}

	claims, err := signer.Verify(tokenStr)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Sub != sub.String() || claims.Sid != sid.String() || claims.Jti != jti {
		t.Errorf("Verify: claims mismatch sub=%s sid=%s jti=%s", claims.Sub, claims.Sid, claims.Jti)
	}
}

func TestVerify_TamperedTokenFails(t *testing.T) {
	key, _ := GenerateKey()
	signer := NewSigner(key)

	tokenStr, _ := signer.Sign(uuid.New(), uuid.New(), uuid.New(), 1, "jti", time.Hour)
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid JWT format: %d parts", len(parts))
	}
	tampered := parts[0] + "." + parts[1] + ".xxx"

	_, err := signer.Verify(tampered)
	if err == nil {
		t.Error("Verify: tampered token should fail")
	}
}

func TestSignIDToken(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer := NewSigner(key)

	iss := "https://auth.example.com"
	sub := "user-uuid"
	aud := "client-uuid"
	nonce := "nonce123"
	authTime := time.Now().Add(-5 * time.Minute)

	tokenStr, err := signer.SignIDToken(iss, sub, aud, nonce, authTime, time.Hour)
	if err != nil {
		t.Fatalf("SignIDToken: %v", err)
	}
	if tokenStr == "" {
		t.Error("SignIDToken: empty token")
	}
	// ID Token は 3 部構成（header.payload.sig）
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		t.Errorf("SignIDToken: invalid JWT format, got %d parts", len(parts))
	}
}

func TestExportJWKSJSON(t *testing.T) {
	key, _ := GenerateKey()
	signer := NewSigner(key)

	jsonStr, err := signer.ExportJWKSJSON()
	if err != nil {
		t.Fatalf("ExportJWKSJSON: %v", err)
	}
	if jsonStr == "" {
		t.Error("ExportJWKSJSON: empty")
	}
	if !strings.Contains(jsonStr, `"keys"`) {
		t.Error("ExportJWKSJSON: missing keys")
	}
	if !strings.Contains(jsonStr, `"kid"`) {
		t.Error("ExportJWKSJSON: missing kid")
	}
	if !strings.Contains(jsonStr, `"alg":"RS256"`) {
		t.Error("ExportJWKSJSON: missing alg RS256")
	}
	if !strings.Contains(jsonStr, `"kty":"RSA"`) {
		t.Error("ExportJWKSJSON: missing kty RSA")
	}
	if !strings.Contains(jsonStr, `"n"`) || !strings.Contains(jsonStr, `"e"`) {
		t.Error("ExportJWKSJSON: missing n or e")
	}
}
