package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestDiscoveryHandler_Get(t *testing.T) {
	h := NewDiscoveryHandler("https://auth.example.com")

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := h.Get(c); err != nil {
		t.Fatalf("Get: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status=%d, want 200", rec.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse JSON: %v", err)
	}

	if v, ok := body["issuer"].(string); !ok || v == "" {
		t.Errorf("issuer missing or empty: %v", body["issuer"])
	}
	if v, ok := body["jwks_uri"].(string); !ok || v == "" {
		t.Errorf("jwks_uri missing or empty: %v", body["jwks_uri"])
	}

	rt, ok := body["response_types_supported"].([]interface{})
	if !ok {
		t.Fatalf("response_types_supported not array: %T", body["response_types_supported"])
	}
	if !contains(rt, "code") {
		t.Errorf("response_types_supported must contain 'code': %v", rt)
	}

	ccm, ok := body["code_challenge_methods_supported"].([]interface{})
	if !ok {
		t.Fatalf("code_challenge_methods_supported not array: %T", body["code_challenge_methods_supported"])
	}
	if !contains(ccm, "S256") {
		t.Errorf("code_challenge_methods_supported must contain 'S256': %v", ccm)
	}
}

func contains(slice []interface{}, s string) bool {
	for _, v := range slice {
		if str, ok := v.(string); ok && str == s {
			return true
		}
	}
	return false
}
