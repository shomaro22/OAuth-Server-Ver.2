package authorize

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/authcode"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/port"
)

type mockAuthCodeRepo struct {
	saveErr error
}

func (m *mockAuthCodeRepo) Save(ctx context.Context, code *authcode.AuthorizationCode) error {
	return m.saveErr
}

func (m *mockAuthCodeRepo) FindByCodeHash(ctx context.Context, codeHash string) (*authcode.AuthorizationCode, error) {
	return nil, nil
}

func (m *mockAuthCodeRepo) FindByCodeHashForUpdate(ctx context.Context, codeHash string) (*authcode.AuthorizationCode, error) {
	return nil, nil
}

func (m *mockAuthCodeRepo) MarkConsumed(ctx context.Context, id uuid.UUID) (int64, error) {
	return 0, nil
}

func (m *mockAuthCodeRepo) Delete(ctx context.Context, id uuid.UUID) error {
	return nil
}

type mockClientRepo struct {
	valid  bool
	exists bool
	err    error
}

func (m *mockClientRepo) Exists(ctx context.Context, clientID uuid.UUID) (bool, error) {
	return m.exists, m.err
}

func (m *mockClientRepo) ValidateRedirectURI(ctx context.Context, clientID uuid.UUID, redirectURI string) (bool, error) {
	return m.valid, m.err
}

func (m *mockClientRepo) ValidateClientCredentials(ctx context.Context, clientID uuid.UUID, clientSecret string) (bool, error) {
	return false, nil
}

func (m *mockClientRepo) GetAllowedScopes(ctx context.Context, clientID uuid.UUID) ([]string, error) {
	return []string{"openid", "profile", "email"}, nil
}

type mockAuthReqRepo struct {
	getReq    *port.StoredAuthorizationRequest
	getErr    error
	deleteErr error
}

func (m *mockAuthReqRepo) Save(ctx context.Context, challenge string, req *port.StoredAuthorizationRequest, ttl time.Duration) error {
	return nil
}

func (m *mockAuthReqRepo) Get(ctx context.Context, challenge string) (*port.StoredAuthorizationRequest, error) {
	return m.getReq, m.getErr
}

func (m *mockAuthReqRepo) Delete(ctx context.Context, challenge string) error {
	return m.deleteErr
}

func TestUseCase_ValidateAuthorizeRequest_InvalidRedirectURI(t *testing.T) {
	uc := NewUseCase(&mockAuthCodeRepo{}, &mockClientRepo{valid: false}, &mockAuthReqRepo{})

	err := uc.ValidateAuthorizeRequest(context.Background(), &ValidateAuthorizeInput{
		ClientID:            uuid.New(),
		RedirectURI:         "https://evil.com/cb",
		ResponseType:        "code",
		CodeChallenge:       "x",
		CodeChallengeMethod: authcode.CodeChallengeMethodS256,
		State:               "s",
	})
	if err != ErrInvalidRedirectURI {
		t.Errorf("expected ErrInvalidRedirectURI, got %v", err)
	}
}

func TestUseCase_ValidateAuthorizeRequest_InvalidResponseType(t *testing.T) {
	uc := NewUseCase(&mockAuthCodeRepo{}, &mockClientRepo{valid: true}, &mockAuthReqRepo{})

	err := uc.ValidateAuthorizeRequest(context.Background(), &ValidateAuthorizeInput{
		ClientID:            uuid.New(),
		RedirectURI:         "https://example.com/cb",
		ResponseType:        "token",
		CodeChallenge:       "x",
		CodeChallengeMethod: authcode.CodeChallengeMethodS256,
		State:               "s",
	})
	if err != ErrInvalidResponseType {
		t.Errorf("expected ErrInvalidResponseType, got %v", err)
	}
}

func TestUseCase_ValidateAuthorizeRequest_Success(t *testing.T) {
	uc := NewUseCase(&mockAuthCodeRepo{}, &mockClientRepo{valid: true}, &mockAuthReqRepo{})

	err := uc.ValidateAuthorizeRequest(context.Background(), &ValidateAuthorizeInput{
		ClientID:            uuid.New(),
		RedirectURI:         "https://example.com/cb",
		ResponseType:        "code",
		CodeChallenge:       "x",
		CodeChallengeMethod: authcode.CodeChallengeMethodS256,
		State:               "s",
	})
	if err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestUseCase_CreateLoginChallenge_Success(t *testing.T) {
	uc := NewUseCase(&mockAuthCodeRepo{}, &mockClientRepo{}, &mockAuthReqRepo{})

	challenge, redirectURL, err := uc.CreateLoginChallenge(context.Background(), &StoredAuthParams{
		ClientID:            "client-uuid",
		RedirectURI:         "https://example.com/cb",
		ResponseType:        "code",
		Scope:                "openid",
		State:                "s",
		LoginURL:             "http://localhost:5173/login",
	})
	if err != nil {
		t.Fatalf("CreateLoginChallenge: %v", err)
	}
	if challenge == "" {
		t.Error("challenge is empty")
	}
	if redirectURL == "" || !strings.Contains(redirectURL, "login_challenge=") {
		t.Errorf("redirectURL invalid: %s", redirectURL)
	}
}

func TestUseCase_GetChallenge_Success(t *testing.T) {
	req := &port.StoredAuthorizationRequest{
		ClientID: "c1", RedirectURI: "https://example.com/cb", State: "s",
	}
	uc := NewUseCase(&mockAuthCodeRepo{}, &mockClientRepo{}, &mockAuthReqRepo{getReq: req})

	got, err := uc.GetChallenge(context.Background(), "ch-1")
	if err != nil {
		t.Fatalf("GetChallenge: %v", err)
	}
	if got.ClientID != "c1" || got.RedirectURI != "https://example.com/cb" || got.State != "s" {
		t.Errorf("GetChallenge: output mismatch %+v", got)
	}
}

func TestUseCase_GetChallenge_NotFound(t *testing.T) {
	uc := NewUseCase(&mockAuthCodeRepo{}, &mockClientRepo{}, &mockAuthReqRepo{getReq: nil})

	_, err := uc.GetChallenge(context.Background(), "unknown")
	if err != ErrChallengeNotFound {
		t.Errorf("expected ErrChallengeNotFound, got %v", err)
	}
}

func TestUseCase_ConsumeChallenge_Success(t *testing.T) {
	uc := NewUseCase(&mockAuthCodeRepo{}, &mockClientRepo{}, &mockAuthReqRepo{})

	err := uc.ConsumeChallenge(context.Background(), "ch-1")
	if err != nil {
		t.Errorf("ConsumeChallenge: %v", err)
	}
}

func TestUseCase_ConsumeChallenge_DeleteError(t *testing.T) {
	uc := NewUseCase(&mockAuthCodeRepo{}, &mockClientRepo{}, &mockAuthReqRepo{deleteErr: errors.New("redis down")})

	err := uc.ConsumeChallenge(context.Background(), "ch-1")
	if err == nil {
		t.Error("expected error")
	}
}

func TestUseCase_GetAndConsumeChallenge_NotFound(t *testing.T) {
	uc := NewUseCase(&mockAuthCodeRepo{}, &mockClientRepo{}, &mockAuthReqRepo{getReq: nil})

	_, err := uc.GetAndConsumeChallenge(context.Background(), "unknown")
	if err != ErrChallengeNotFound {
		t.Errorf("expected ErrChallengeNotFound, got %v", err)
	}
}

func TestUseCase_GetAndConsumeChallenge_DeleteError(t *testing.T) {
	req := &port.StoredAuthorizationRequest{ClientID: "c", RedirectURI: "https://example.com/cb"}
	uc := NewUseCase(&mockAuthCodeRepo{}, &mockClientRepo{}, &mockAuthReqRepo{getReq: req, deleteErr: errors.New("redis down")})

	_, err := uc.GetAndConsumeChallenge(context.Background(), "ch-1")
	if err == nil {
		t.Error("expected error")
	}
}

func TestUseCase_GetAndConsumeChallenge_Success(t *testing.T) {
	req := &port.StoredAuthorizationRequest{
		ClientID: "client-1", RedirectURI: "https://example.com/cb",
		CodeChallenge: "ch", CodeChallengeMethod: "S256", State: "s",
	}
	uc := NewUseCase(&mockAuthCodeRepo{}, &mockClientRepo{}, &mockAuthReqRepo{getReq: req})

	out, err := uc.GetAndConsumeChallenge(context.Background(), "ch-123")
	if err != nil {
		t.Fatalf("GetAndConsumeChallenge: %v", err)
	}
	if out.ClientID != "client-1" || out.RedirectURI != "https://example.com/cb" || out.CodeChallenge != "ch" {
		t.Errorf("output mismatch: %+v", out)
	}
}

func TestUseCase_IssueCode_Success(t *testing.T) {
	uc := NewUseCase(
		&mockAuthCodeRepo{},
		&mockClientRepo{valid: true, exists: true},
		&mockAuthReqRepo{},
	)

	sessionID := uuid.New()
	in := &IssueCodeInput{
		ResponseType:        "code",
		UserID:              uuid.New(),
		SessionID:           sessionID,
		ClientID:            uuid.New(),
		RedirectURI:         "https://example.com/callback",
		Scopes:              "openid",
		State:               "xyz",
		Nonce:               "n-123",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: authcode.CodeChallengeMethodS256,
	}

	out, err := uc.IssueCode(context.Background(), in)
	if err != nil {
		t.Fatalf("IssueCode: unexpected error: %v", err)
	}
	if out.Code == "" {
		t.Error("IssueCode: expected non-empty code")
	}
	if out.RedirectURI != in.RedirectURI {
		t.Errorf("IssueCode: redirect_uri = %s, want %s", out.RedirectURI, in.RedirectURI)
	}
	if out.State != in.State {
		t.Errorf("IssueCode: state = %s, want %s", out.State, in.State)
	}
}

func TestUseCase_IssueCode_UnsupportedPKCE(t *testing.T) {
	uc := NewUseCase(
		&mockAuthCodeRepo{},
		&mockClientRepo{valid: true, exists: true},
		&mockAuthReqRepo{},
	)

	in := &IssueCodeInput{
		ResponseType:        "code",
		UserID:              uuid.New(),
		SessionID:           uuid.New(),
		ClientID:            uuid.New(),
		RedirectURI:         "https://example.com/callback",
		Scopes:              "openid",
		State:               "xyz",
		Nonce:               "",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "plain",
	}

	_, err := uc.IssueCode(context.Background(), in)
	if err == nil {
		t.Fatal("IssueCode: expected error for plain PKCE")
	}
	if !errors.Is(err, ErrUnsupportedPKCE) {
		t.Errorf("IssueCode: expected ErrUnsupportedPKCE, got %v", err)
	}
}

func TestUseCase_IssueCode_InvalidRedirectURI(t *testing.T) {
	uc := NewUseCase(
		&mockAuthCodeRepo{},
		&mockClientRepo{valid: false, exists: true},
		&mockAuthReqRepo{},
	)

	in := &IssueCodeInput{
		ResponseType:        "code",
		UserID:              uuid.New(),
		SessionID:           uuid.New(),
		ClientID:            uuid.New(),
		RedirectURI:         "https://evil.com/callback",
		Scopes:              "openid",
		State:               "xyz",
		Nonce:               "",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: authcode.CodeChallengeMethodS256,
	}

	_, err := uc.IssueCode(context.Background(), in)
	if err == nil {
		t.Fatal("IssueCode: expected error for invalid redirect_uri")
	}
	if !errors.Is(err, ErrInvalidRedirectURI) {
		t.Errorf("IssueCode: expected ErrInvalidRedirectURI, got %v", err)
	}
}

func TestUseCase_IssueCode_WithSessionID(t *testing.T) {
	userID := uuid.New()
	sessionID := uuid.New()

	uc := NewUseCase(
		&mockAuthCodeRepo{},
		&mockClientRepo{valid: true, exists: true},
		&mockAuthReqRepo{},
	)

	in := &IssueCodeInput{
		ResponseType:        "code",
		UserID:             userID,
		SessionID:          sessionID,
		ClientID:           uuid.New(),
		RedirectURI:        "https://example.com/callback",
		Scopes:             "openid",
		State:               "xyz",
		Nonce:               "n-456",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: authcode.CodeChallengeMethodS256,
	}

	out, err := uc.IssueCode(context.Background(), in)
	if err != nil {
		t.Fatalf("IssueCode: unexpected error: %v", err)
	}
	if out.Code == "" {
		t.Error("IssueCode: expected non-empty code")
	}
}
