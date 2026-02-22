package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/usecase/userinfo"
)

// --- 手書きモック（userinfo.Interactor） ---
type mockUserInfoInteractor struct {
	t           *testing.T
	gotToken    string
	retOut      *userinfo.GetOutput
	retErr      error
	expectToken string
	called      bool
}

func (m *mockUserInfoInteractor) Get(ctx context.Context, in *userinfo.GetInput) (*userinfo.GetOutput, error) {
	m.called = true
	if in == nil {
		m.t.Fatalf("input is nil")
	}
	m.gotToken = in.AccessToken
	if m.expectToken != "" && m.gotToken != m.expectToken {
		m.t.Fatalf("unexpected token: got=%q want=%q", m.gotToken, m.expectToken)
	}
	return m.retOut, m.retErr
}

func TestUserInfoHandler_Get_Unauthorized_WhenNoAuthorizationHeader(t *testing.T) {
	e := echo.New()

	uc := &mockUserInfoInteractor{t: t}
	h := NewUserInfoHandler(uc)

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := h.Get(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got=%d want=%d body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	if uc.called {
		t.Fatalf("usecase should not be called when Authorization header is missing")
	}

	var body map[string]string
	_ = json.NewDecoder(strings.NewReader(rec.Body.String())).Decode(&body)
	if body["error"] != "invalid_token" {
		t.Fatalf("body.error: got=%q want=%q body=%s", body["error"], "invalid_token", rec.Body.String())
	}
}

func TestUserInfoHandler_Get_Unauthorized_WhenNotBearer(t *testing.T) {
	e := echo.New()

	uc := &mockUserInfoInteractor{t: t}
	h := NewUserInfoHandler(uc)

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Basic abcdef")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := h.Get(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got=%d want=%d body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	if uc.called {
		t.Fatalf("usecase should not be called when Authorization header is not Bearer")
	}
}

func TestUserInfoHandler_Get_Unauthorized_WhenUsecaseReturnsInvalidToken(t *testing.T) {
	e := echo.New()

	uc := &mockUserInfoInteractor{
		t:           t,
		retErr:      userinfo.ErrInvalidToken,
		expectToken: "VALID",
	}
	h := NewUserInfoHandler(uc)

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer VALID")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := h.Get(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if !uc.called {
		t.Fatalf("usecase should be called")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got=%d want=%d body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

func TestUserInfoHandler_Get_InternalServerError_WhenUsecaseReturnsUnknownError(t *testing.T) {
	e := echo.New()

	uc := &mockUserInfoInteractor{
		t:           t,
		retErr:      errors.New("boom"),
		expectToken: "VALID",
	}
	h := NewUserInfoHandler(uc)

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer VALID")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := h.Get(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got=%d want=%d body=%s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
}

func TestUserInfoHandler_Get_OK(t *testing.T) {
	e := echo.New()

	out := &userinfo.GetOutput{
		Sub: "user-123",
		// もし他フィールドがあるならここで入れてOK
	}
	uc := &mockUserInfoInteractor{
		t:           t,
		retOut:      out,
		expectToken: "ACCESS",
	}
	h := NewUserInfoHandler(uc)

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer ACCESS")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := h.Get(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got=%d want=%d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var got userinfo.GetOutput
	if err := json.NewDecoder(strings.NewReader(rec.Body.String())).Decode(&got); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if got.Sub != "user-123" {
		t.Fatalf("sub: got=%q want=%q", got.Sub, "user-123")
	}
}
