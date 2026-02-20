package authorize

import (
	"context"
	"errors"
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

type mockAuthReqRepo struct{}

func (m *mockAuthReqRepo) Save(ctx context.Context, challenge string, req *port.StoredAuthorizationRequest, ttl time.Duration) error {
	return nil
}

func (m *mockAuthReqRepo) Get(ctx context.Context, challenge string) (*port.StoredAuthorizationRequest, error) {
	return nil, nil
}

func (m *mockAuthReqRepo) Delete(ctx context.Context, challenge string) error {
	return nil
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
