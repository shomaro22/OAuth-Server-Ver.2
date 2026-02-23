package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/usecase/logout"
)

type mockLogoutUseCase struct {
	logoutErr error
}

func (m *mockLogoutUseCase) Logout(ctx context.Context, in *logout.LogoutInput) error {
	return m.logoutErr
}

func TestLogoutHandler_Post_NoCookie_200(t *testing.T) {
	uc := &mockLogoutUseCase{}
	h := NewLogoutHandler(uc)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/sessions/logout", strings.NewReader(""))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.Post(c)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status=%d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "logged out") {
		t.Errorf("body=%q", rec.Body.String())
	}
}

func TestLogoutHandler_Post_Success_200(t *testing.T) {
	uc := &mockLogoutUseCase{}
	h := NewLogoutHandler(uc)

	req := httptest.NewRequest(http.MethodPost, "/sessions/logout", strings.NewReader(""))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-token"})
	rec := httptest.NewRecorder()
	e := echo.New()
	c := e.NewContext(req, rec)

	err := h.Post(c)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status=%d, want 200", rec.Code)
	}
}
