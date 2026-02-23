package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/usecase/authorize"
)

type mockAuthorizeUseCase struct {
	validateErr        error
	createChallengeURL string
	createChallengeErr error

	getChallengeParam *authorize.StoredAuthParams
	getChallengeErr   error

	getConsumeParam *authorize.StoredAuthParams
	getConsumeErr   error

	issueCodeOut *authorize.IssueCodeOutput
	issueCodeErr error
}

func (m *mockAuthorizeUseCase) ValidateAuthorizeRequest(ctx context.Context, in *authorize.ValidateAuthorizeInput) error {
	return m.validateErr
}
func (m *mockAuthorizeUseCase) CreateLoginChallenge(ctx context.Context, params *authorize.StoredAuthParams) (string, string, error) {
	if m.createChallengeErr != nil {
		return "", "", m.createChallengeErr
	}
	return "ch123", m.createChallengeURL, nil
}
func (m *mockAuthorizeUseCase) GetChallenge(ctx context.Context, challenge string) (*authorize.StoredAuthParams, error) {
	return m.getChallengeParam, m.getChallengeErr
}
func (m *mockAuthorizeUseCase) GetAndConsumeChallenge(ctx context.Context, challenge string) (*authorize.StoredAuthParams, error) {
	return m.getConsumeParam, m.getConsumeErr
}
func (m *mockAuthorizeUseCase) ConsumeChallenge(ctx context.Context, challenge string) error {
	return nil
}
func (m *mockAuthorizeUseCase) IssueCode(ctx context.Context, in *authorize.IssueCodeInput) (*authorize.IssueCodeOutput, error) {
	if m.issueCodeErr != nil {
		return nil, m.issueCodeErr
	}
	if m.issueCodeOut != nil {
		return m.issueCodeOut, nil
	}
	return &authorize.IssueCodeOutput{Code: "code", RedirectURI: in.RedirectURI, State: in.State}, nil
}

type mockSessionResolver struct {
	sessionID uuid.UUID
	userID    uuid.UUID
	ok        bool
	err       error
}

func (m *mockSessionResolver) Resolve(ctx context.Context, sessionToken string) (uuid.UUID, uuid.UUID, bool, error) {
	return m.sessionID, m.userID, m.ok, m.err
}

func TestAuthorizeHandler_Get_ParamsMissing_400(t *testing.T) {
	uc := &mockAuthorizeUseCase{}
	resolver := &mockSessionResolver{}
	h := NewAuthorizeHandler(uc, resolver, "http://localhost:5173/login", "http://localhost:5173/consent", "http://localhost:8080")

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.Get(c)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status=%d, want 400", rec.Code)
	}
}

func TestAuthorizeHandler_Get_SessionOK_IssueCode_Redirects(t *testing.T) {
	sid := uuid.New()
	uid := uuid.New()
	uc := &mockAuthorizeUseCase{
		issueCodeOut: &authorize.IssueCodeOutput{Code: "xyz", RedirectURI: "http://localhost:5173/callback", State: "s"},
	}
	resolver := &mockSessionResolver{sessionID: sid, userID: uid, ok: true}
	h := NewAuthorizeHandler(uc, resolver, "http://localhost:5173/login", "http://localhost:5173/consent", "http://localhost:8080")

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?client_id=11111111-1111-1111-1111-111111111111&redirect_uri=http://localhost:5173/callback&response_type=code&scope=openid&state=s&code_challenge=x&code_challenge_method=S256", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.Get(c)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if rec.Code != http.StatusFound {
		t.Errorf("status=%d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "code=xyz") {
		t.Errorf("Location=%q", loc)
	}
}

func TestAuthorizeHandler_Get_NoSession_RedirectsToLogin(t *testing.T) {
	uc := &mockAuthorizeUseCase{createChallengeURL: "http://localhost:5173/login?login_challenge=ch123"}
	resolver := &mockSessionResolver{ok: false}
	h := NewAuthorizeHandler(uc, resolver, "http://localhost:5173/login", "http://localhost:5173/consent", "http://localhost:8080")

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?client_id=11111111-1111-1111-1111-111111111111&redirect_uri=http://localhost:5173/callback&response_type=code&scope=openid&state=s&code_challenge=x&code_challenge_method=S256", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.Get(c)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if rec.Code != http.StatusFound {
		t.Errorf("status=%d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if loc == "" || loc != "http://localhost:5173/login?login_challenge=ch123" {
		t.Errorf("Location=%q", loc)
	}
}

func TestAuthorizeHandler_GetContinue_ChallengeMissing_400(t *testing.T) {
	uc := &mockAuthorizeUseCase{}
	resolver := &mockSessionResolver{}
	h := NewAuthorizeHandler(uc, resolver, "http://localhost:5173/login", "http://localhost:5173/consent", "http://localhost:8080")

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize/continue", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.GetContinue(c)
	if err != nil {
		t.Fatalf("GetContinue: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status=%d, want 400", rec.Code)
	}
}

func TestAuthorizeHandler_GetDeny_ChallengeMissing_400(t *testing.T) {
	uc := &mockAuthorizeUseCase{}
	resolver := &mockSessionResolver{}
	h := NewAuthorizeHandler(uc, resolver, "http://localhost:5173/login", "http://localhost:5173/consent", "http://localhost:8080")

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize/deny", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.GetDeny(c)
	if err != nil {
		t.Fatalf("GetDeny: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status=%d, want 400", rec.Code)
	}
}

// TestAuthorizeHandler_Get_ValidateError_TriggersAuthorizeErrorResponse は authorizeErrorResponse を踏む。
func TestAuthorizeHandler_Get_ValidateError_TriggersAuthorizeErrorResponse(t *testing.T) {
	uc := &mockAuthorizeUseCase{validateErr: authorize.ErrInvalidRedirectURI}
	resolver := &mockSessionResolver{ok: false}
	h := NewAuthorizeHandler(uc, resolver, "http://localhost:5173/login", "http://localhost:5173/consent", "http://localhost:8080")

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?client_id=11111111-1111-1111-1111-111111111111&redirect_uri=http://localhost:5173/callback&response_type=code&scope=openid&state=s&code_challenge=x&code_challenge_method=S256", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.Get(c)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status=%d, want 400", rec.Code)
	}
	if body := rec.Body.String(); body != "" && !strings.Contains(body, "redirect_uri") {
		t.Errorf("body should mention redirect_uri: %q", body)
	}
}

func TestAuthorizeHandler_Get_ValidateError_ErrInvalidResponseType(t *testing.T) {
	uc := &mockAuthorizeUseCase{validateErr: authorize.ErrInvalidResponseType}
	resolver := &mockSessionResolver{ok: false}
	h := NewAuthorizeHandler(uc, resolver, "http://localhost:5173/login", "http://localhost:5173/consent", "http://localhost:8080")

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?client_id=11111111-1111-1111-1111-111111111111&redirect_uri=http://localhost:5173/callback&response_type=token&scope=openid&state=s&code_challenge=x&code_challenge_method=S256", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.Get(c)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status=%d, want 400", rec.Code)
	}
}

func TestAuthorizeHandler_Get_ValidateError_ErrInvalidScope(t *testing.T) {
	uc := &mockAuthorizeUseCase{validateErr: authorize.ErrInvalidScope}
	resolver := &mockSessionResolver{ok: false}
	h := NewAuthorizeHandler(uc, resolver, "http://localhost:5173/login", "http://localhost:5173/consent", "http://localhost:8080")

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?client_id=11111111-1111-1111-1111-111111111111&redirect_uri=http://localhost:5173/callback&response_type=code&scope=openid&state=s&code_challenge=x&code_challenge_method=S256", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.Get(c)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status=%d, want 400", rec.Code)
	}
}

func TestAuthorizeHandler_GetDeny_Success_RedirectsAccessDenied(t *testing.T) {
	stored := &authorize.StoredAuthParams{RedirectURI: "http://localhost:5173/callback", State: "s"}
	uc := &mockAuthorizeUseCase{getChallengeParam: stored}
	resolver := &mockSessionResolver{}
	h := NewAuthorizeHandler(uc, resolver, "http://localhost:5173/login", "http://localhost:5173/consent", "http://localhost:8080")

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize/deny?login_challenge=ch1", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.GetDeny(c)
	if err != nil {
		t.Fatalf("GetDeny: %v", err)
	}
	if rec.Code != http.StatusFound {
		t.Errorf("status=%d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "error=access_denied") || !strings.Contains(loc, "state=s") {
		t.Errorf("Location=%q", loc)
	}
}

func TestAuthorizeHandler_Get_IssueCodeError_ServerError_500(t *testing.T) {
	uc := &mockAuthorizeUseCase{issueCodeErr: errors.New("internal")}
	resolver := &mockSessionResolver{sessionID: uuid.New(), userID: uuid.New(), ok: true}
	h := NewAuthorizeHandler(uc, resolver, "http://localhost:5173/login", "http://localhost:5173/consent", "http://localhost:8080")

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?client_id=11111111-1111-1111-1111-111111111111&redirect_uri=http://localhost:5173/callback&response_type=code&scope=openid&state=s&code_challenge=x&code_challenge_method=S256", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.Get(c)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status=%d, want 500", rec.Code)
	}
}

func TestAuthorizeHandler_Get_IssueCodeError_TriggersAuthorizeErrorResponse(t *testing.T) {
	uc := &mockAuthorizeUseCase{issueCodeErr: authorize.ErrInvalidScope}
	resolver := &mockSessionResolver{sessionID: uuid.New(), userID: uuid.New(), ok: true}
	h := NewAuthorizeHandler(uc, resolver, "http://localhost:5173/login", "http://localhost:5173/consent", "http://localhost:8080")

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?client_id=11111111-1111-1111-1111-111111111111&redirect_uri=http://localhost:5173/callback&response_type=code&scope=openid&state=s&code_challenge=x&code_challenge_method=S256", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.Get(c)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status=%d, want 400", rec.Code)
	}
}

func TestAuthorizeHandler_GetContinue_IssueCodeError_400(t *testing.T) {
	uc := &mockAuthorizeUseCase{
		getConsumeParam: &authorize.StoredAuthParams{ClientID: "11111111-1111-1111-1111-111111111111", RedirectURI: "http://localhost:5173/callback", State: "s"},
		issueCodeErr:    authorize.ErrInvalidScope,
	}
	resolver := &mockSessionResolver{sessionID: uuid.New(), userID: uuid.New(), ok: true}
	h := NewAuthorizeHandler(uc, resolver, "http://localhost:5173/login", "http://localhost:5173/consent", "http://localhost:8080")

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize/continue?login_challenge=ch1&approved=true", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.GetContinue(c)
	if err != nil {
		t.Fatalf("GetContinue: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status=%d, want 400", rec.Code)
	}
}

func TestAuthorizeHandler_GetContinue_SessionOK_IssueCode_Redirects(t *testing.T) {
	sid := uuid.New()
	uid := uuid.New()
	stored := &authorize.StoredAuthParams{
		ClientID: "11111111-1111-1111-1111-111111111111",
		RedirectURI: "http://localhost:5173/callback",
		State: "s",
	}
	uc := &mockAuthorizeUseCase{
		getConsumeParam: stored,
		issueCodeOut:    &authorize.IssueCodeOutput{Code: "abc", RedirectURI: "http://localhost:5173/callback", State: "s"},
	}
	resolver := &mockSessionResolver{sessionID: sid, userID: uid, ok: true}
	h := NewAuthorizeHandler(uc, resolver, "http://localhost:5173/login", "http://localhost:5173/consent", "http://localhost:8080")

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize/continue?login_challenge=ch1&approved=true", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.GetContinue(c)
	if err != nil {
		t.Fatalf("GetContinue: %v", err)
	}
	if rec.Code != http.StatusFound {
		t.Errorf("status=%d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "code=abc") {
		t.Errorf("Location=%q", loc)
	}
}
