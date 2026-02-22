package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/infrastructure/jwt"
)

func TestJWKSHandler_Get(t *testing.T) {
	key, err := jwt.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer := jwt.NewSigner(key)

	h := NewJWKSHandler(signer)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/jwks", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := h.Get(c); err != nil {
		t.Fatalf("Get: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status=%d, want 200", rec.Code)
	}

	var body struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Use string `json:"use"`
			Alg string `json:"alg"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse JSON: %v", err)
	}

	if len(body.Keys) == 0 {
		t.Fatal("keys array is empty")
	}

	k := body.Keys[0]
	if k.Kid == "" {
		t.Error("kid is required")
	}
	if k.Kty != "RSA" {
		t.Errorf("kty=%s, want RSA", k.Kty)
	}
	if k.Use != "sig" {
		t.Errorf("use=%s, want sig", k.Use)
	}
	if k.Alg != "RS256" {
		t.Errorf("alg=%s, want RS256", k.Alg)
	}
}
