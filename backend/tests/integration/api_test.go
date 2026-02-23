//go:build integration

package integration

import (
	"net/http"
	"os"
	"strings"
	"testing"
)

func getBaseURL() string {
	if u := os.Getenv("BASE_URL"); u != "" {
		return u
	}
	return "http://localhost:8080"
}

func TestIntegration_API(t *testing.T) {
	base := getBaseURL()

	t.Run("GET /health → 200", func(t *testing.T) {
		res, err := http.Get(base + "/health")
		if err != nil {
			t.Fatalf("health: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Errorf("status=%d, want 200", res.StatusCode)
		}
		t.Logf("GET /health → %d OK", res.StatusCode)
	})

	t.Run("GET /.well-known/openid-configuration → 200 issuer/jwks_uri あり", func(t *testing.T) {
		res, err := http.Get(base + "/.well-known/openid-configuration")
		if err != nil {
			t.Fatalf("discovery: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Errorf("status=%d, want 200", res.StatusCode)
		}
		body := make([]byte, 4096)
		n, _ := res.Body.Read(body)
		body = body[:n]
		if !contains(body, []byte("issuer")) || !contains(body, []byte("jwks_uri")) {
			t.Error("discovery: issuer or jwks_uri missing")
		}
		t.Logf("GET /.well-known/openid-configuration → %d OK (issuer, jwks_uri)", res.StatusCode)
	})

	t.Run("GET /jwks → 200 keys[] あり", func(t *testing.T) {
		res, err := http.Get(base + "/jwks")
		if err != nil {
			t.Fatalf("jwks: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Errorf("status=%d, want 200", res.StatusCode)
		}
		body := make([]byte, 4096)
		n, _ := res.Body.Read(body)
		body = body[:n]
		if !contains(body, []byte("keys")) {
			t.Error("jwks: keys missing")
		}
		t.Logf("GET /jwks → %d OK (keys)", res.StatusCode)
	})
}

func contains(b, sub []byte) bool {
	for i := 0; i <= len(b)-len(sub); i++ {
		if string(b[i:i+len(sub)]) == string(sub) {
			return true
		}
	}
	return false
}

func TestIntegration_TokenFailure(t *testing.T) {
	base := getBaseURL()

	t.Run("POST /oauth/token invalid_grant（code不正）→ 400", func(t *testing.T) {
		res, err := http.Post(base+"/oauth/token", "application/x-www-form-urlencoded",
			strings.NewReader("grant_type=authorization_code&code=invalid&redirect_uri=http://localhost:5173/callback&client_id=11111111-1111-1111-1111-111111111111&code_verifier=x"))
		if err != nil {
			t.Fatalf("token: %v", err)
		}
		defer res.Body.Close()
		body := make([]byte, 512)
		n, _ := res.Body.Read(body)
		body = body[:n]
		if res.StatusCode != 400 {
			t.Errorf("status=%d, want 400", res.StatusCode)
		}
		if !contains(body, []byte("invalid_grant")) && !contains(body, []byte("invalid_request")) {
			t.Errorf("body should contain invalid_grant or invalid_request: %s", string(body))
		}
		t.Logf("POST /oauth/token (invalid code) → %d invalid_grant", res.StatusCode)
	})
}

func TestIntegration_UserInfo(t *testing.T) {
	base := getBaseURL()

	t.Run("GET /userinfo Bearer なし → 401", func(t *testing.T) {
		res, err := http.Get(base + "/userinfo")
		if err != nil {
			t.Fatalf("userinfo: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != 401 {
			t.Errorf("status=%d, want 401", res.StatusCode)
		}
		t.Logf("GET /userinfo (no Bearer) → %d", res.StatusCode)
	})
}
