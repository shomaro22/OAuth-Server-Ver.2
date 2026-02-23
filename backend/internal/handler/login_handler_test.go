package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/user"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/port"
	sessentity "github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/session"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/usecase/login"
)

type mockLoginUserRepo struct {
	user         *user.User
	passwordHash string
	err          error
}

func (m *mockLoginUserRepo) FindByID(ctx context.Context, id uuid.UUID) (*user.User, error) { return nil, nil }
func (m *mockLoginUserRepo) FindByUsername(ctx context.Context, username string) (*user.User, string, error) {
	return m.user, m.passwordHash, m.err
}
func (m *mockLoginUserRepo) Save(ctx context.Context, u *user.User) error { return nil }

type mockLoginSessionRepo struct{}

func (m *mockLoginSessionRepo) Save(ctx context.Context, s *sessentity.Session) error { return nil }
func (m *mockLoginSessionRepo) FindByID(ctx context.Context, sid uuid.UUID) (*sessentity.Session, error) {
	return nil, nil
}
func (m *mockLoginSessionRepo) FindBySessionTokenHash(ctx context.Context, tokenHash string) (*sessentity.Session, error) {
	return nil, nil
}
func (m *mockLoginSessionRepo) IncrementTokenVersion(ctx context.Context, sid uuid.UUID) error { return nil }
func (m *mockLoginSessionRepo) Revoke(ctx context.Context, sid uuid.UUID) error                { return nil }

type mockLoginAuthReqRepo struct {
	req *port.StoredAuthorizationRequest
	err error
}

func (m *mockLoginAuthReqRepo) Save(ctx context.Context, challenge string, req *port.StoredAuthorizationRequest, ttl time.Duration) error {
	return nil
}
func (m *mockLoginAuthReqRepo) Get(ctx context.Context, challenge string) (*port.StoredAuthorizationRequest, error) {
	return m.req, m.err
}
func (m *mockLoginAuthReqRepo) Delete(ctx context.Context, challenge string) error { return nil }

func TestLoginHandler_Post_InvalidBody_400(t *testing.T) {
	uc := login.NewUseCase(&mockLoginUserRepo{}, &mockLoginSessionRepo{}, &mockLoginAuthReqRepo{}, "https://server")
	h := NewLoginHandler(uc)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/sessions/login", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")
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

func TestLoginHandler_Post_InvalidCredentials_401(t *testing.T) {
	uc := login.NewUseCase(
		&mockLoginUserRepo{user: nil, passwordHash: ""},
		&mockLoginSessionRepo{},
		&mockLoginAuthReqRepo{req: &port.StoredAuthorizationRequest{}},
		"https://server",
	)
	h := NewLoginHandler(uc)

	body := `{"login_challenge":"ch","username":"x","password":"y"}`
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/sessions/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.Post(c)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status=%d, want 401", rec.Code)
	}
}
