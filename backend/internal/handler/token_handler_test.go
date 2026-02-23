package handler

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/usecase/token"
)

type mockTokenInteractor struct {
	exchangeOut *token.TokenOutput
	exchangeErr error
	refreshOut  *token.TokenOutput
	refreshErr  error
}

func (m *mockTokenInteractor) Exchange(ctx context.Context, in *token.ExchangeInput) (*token.TokenOutput, error) {
	return m.exchangeOut, m.exchangeErr
}

func (m *mockTokenInteractor) Refresh(ctx context.Context, in *token.RefreshInput) (*token.TokenOutput, error) {
	return m.refreshOut, m.refreshErr
}

type mockClientRepoForHandler struct{}

func (m *mockClientRepoForHandler) Exists(ctx context.Context, clientID uuid.UUID) (bool, error) {
	return true, nil
}
func (m *mockClientRepoForHandler) ValidateRedirectURI(ctx context.Context, clientID uuid.UUID, redirectURI string) (bool, error) {
	return true, nil
}
func (m *mockClientRepoForHandler) ValidateClientCredentials(ctx context.Context, clientID uuid.UUID, clientSecret string) (bool, error) {
	return false, nil
}
func (m *mockClientRepoForHandler) GetAllowedScopes(ctx context.Context, clientID uuid.UUID) ([]string, error) {
	return []string{"openid"}, nil
}

func TestTokenHandler_Post_InvalidGrantType_400(t *testing.T) {
	uc := &mockTokenInteractor{}
	h := NewTokenHandler(uc, &mockClientRepoForHandler{}, []string{"http://localhost:5173"})

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader("grant_type=invalid"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.Post(c)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status=%d, want 400", rec.Code)
	}
}

func TestTokenHandler_Post_AuthorizationCode_MissingParams_400(t *testing.T) {
	uc := &mockTokenInteractor{}
	h := NewTokenHandler(uc, &mockClientRepoForHandler{}, []string{"http://localhost:5173"})

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader("grant_type=authorization_code"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.Post(c)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status=%d, want 400", rec.Code)
	}
}

func TestTokenHandler_Post_AuthorizationCode_InvalidGrant_400(t *testing.T) {
	uc := &mockTokenInteractor{exchangeErr: token.ErrInvalidCode}
	h := NewTokenHandler(uc, &mockClientRepoForHandler{}, []string{"http://localhost:5173"})

	body := "grant_type=authorization_code&code=x&redirect_uri=http://localhost:5173/callback&client_id=11111111-1111-1111-1111-111111111111&code_verifier=y"
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.Post(c)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status=%d, want 400", rec.Code)
	}
}

func TestTokenHandler_Post_AuthorizationCode_BasicAuth_InvalidClient_401(t *testing.T) {
	uc := &mockTokenInteractor{exchangeErr: token.ErrInvalidCode}
	h := NewTokenHandler(uc, &mockClientRepoForHandler{}, []string{"http://localhost:5173"})

	basic := base64.StdEncoding.EncodeToString([]byte("11111111-1111-1111-1111-111111111111:secret"))
	body := "grant_type=authorization_code&code=x&redirect_uri=http://localhost:5173/callback&client_id=11111111-1111-1111-1111-111111111111&code_verifier=y"
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+basic)

	e := echo.New()
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.Post(c)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	// mockClientRepoForHandler.ValidateClientCredentials は常に false → 401
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status=%d, want 401", rec.Code)
	}
}

func TestTokenHandler_Post_AuthorizationCode_Success_200(t *testing.T) {
	uc := &mockTokenInteractor{
		exchangeOut: &token.TokenOutput{
			AccessToken:  "at",
			TokenType:    "Bearer",
			ExpiresIn:    300,
			Scope:        "openid",
			IDToken:      "id",
			RefreshToken: "rt123",
		},
	}
	h := NewTokenHandler(uc, &mockClientRepoForHandler{}, []string{"http://localhost:5173"})

	body := "grant_type=authorization_code&code=valid&redirect_uri=http://localhost:5173/callback&client_id=11111111-1111-1111-1111-111111111111&code_verifier=verifier"
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.Post(c)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status=%d, want 200", rec.Code)
	}
	// A) Set-Cookie に __Host-rt が含まれる
	setCookie := rec.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "__Host-rt=") || !strings.Contains(setCookie, "rt123") {
		t.Errorf("Set-Cookie: want __Host-rt=rt123, got %q", setCookie)
	}
	// B) JSON に refresh_token が含まれない（仕様）
	bodyStr := rec.Body.String()
	if strings.Contains(bodyStr, "refresh_token") {
		t.Errorf("response body must not contain refresh_token, got %q", bodyStr)
	}
}

func TestTokenHandler_Post_RefreshToken_Success_200(t *testing.T) {
	uc := &mockTokenInteractor{
		refreshOut: &token.TokenOutput{
			AccessToken:  "new-at",
			TokenType:    "Bearer",
			ExpiresIn:    300,
			Scope:        "openid",
			IDToken:      "new-id",
			RefreshToken: "new-rt456",
		},
	}
	h := NewTokenHandler(uc, &mockClientRepoForHandler{}, []string{"http://localhost:5173"})

	body := "grant_type=refresh_token&client_id=11111111-1111-1111-1111-111111111111"
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://localhost:5173")
	req.AddCookie(&http.Cookie{Name: "__Host-rt", Value: "rt123"})

	e := echo.New()
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.Post(c)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status=%d, want 200", rec.Code)
	}
	setCookie := rec.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "__Host-rt=") || !strings.Contains(setCookie, "new-rt456") {
		t.Errorf("Set-Cookie: want new RT, got %q", setCookie)
	}
	if strings.Contains(rec.Body.String(), "refresh_token") {
		t.Errorf("response body must not contain refresh_token")
	}
}

func TestTokenHandler_Post_RefreshToken_OriginNG_403(t *testing.T) {
	uc := &mockTokenInteractor{}
	h := NewTokenHandler(uc, &mockClientRepoForHandler{}, []string{"http://localhost:5173"})

	body := "grant_type=refresh_token&client_id=11111111-1111-1111-1111-111111111111"
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.com")
	req.AddCookie(&http.Cookie{Name: "__Host-rt", Value: "rt123"})

	e := echo.New()
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.Post(c)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status=%d, want 403", rec.Code)
	}
}

func TestTokenHandler_Post_RefreshToken_NoCookie_400(t *testing.T) {
	uc := &mockTokenInteractor{}
	h := NewTokenHandler(uc, &mockClientRepoForHandler{}, []string{"http://localhost:5173"})

	body := "grant_type=refresh_token&client_id=11111111-1111-1111-1111-111111111111"
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://localhost:5173")
	// Cookie なし

	e := echo.New()
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.Post(c)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status=%d, want 400", rec.Code)
	}
}

func TestTokenHandler_Post_RefreshToken_InvalidGrant_400(t *testing.T) {
	uc := &mockTokenInteractor{refreshErr: token.ErrInvalidRefreshToken}
	h := NewTokenHandler(uc, &mockClientRepoForHandler{}, []string{"http://localhost:5173"})

	body := "grant_type=refresh_token&client_id=11111111-1111-1111-1111-111111111111"
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://localhost:5173")
	req.AddCookie(&http.Cookie{Name: "__Host-rt", Value: "rt123"})

	e := echo.New()
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.Post(c)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status=%d, want 400", rec.Code)
	}
	// invalid_grant が返る
	if !strings.Contains(rec.Body.String(), "invalid_grant") {
		t.Errorf("want invalid_grant in body, got %q", rec.Body.String())
	}
}
