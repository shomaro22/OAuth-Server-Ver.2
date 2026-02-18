package authorize

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/authcode"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/session"
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

type mockSessionRepo struct {
	saveErr                error
	findBySessionToken     *session.Session
	findBySessionTokenErr  error
}

func (m *mockSessionRepo) Save(ctx context.Context, s *session.Session) error {
	return m.saveErr
}

func (m *mockSessionRepo) FindBySessionTokenHash(ctx context.Context, tokenHash string) (*session.Session, error) {
	return m.findBySessionToken, m.findBySessionTokenErr
}

func (m *mockSessionRepo) FindByID(ctx context.Context, sid uuid.UUID) (*session.Session, error) {
	return nil, nil
}

func (m *mockSessionRepo) IncrementTokenVersion(ctx context.Context, sid uuid.UUID) error {
	return nil
}

func (m *mockSessionRepo) Revoke(ctx context.Context, sid uuid.UUID) error {
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

func TestUseCase_IssueCode_Success(t *testing.T) {
	uc := NewUseCase(
		&mockAuthCodeRepo{},
		&mockSessionRepo{},
		&mockClientRepo{valid: true, exists: true},
	)

	in := &IssueCodeInput{
		ResponseType:        "code",
		UserID:              uuid.New(),
		ClientID:            uuid.New(),
		RedirectURI:         "https://example.com/callback",
		Scopes:              "openid",
		State:               "xyz",
		Nonce:               "n-123",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: authcode.CodeChallengeMethodS256,
		SessionTokenHash:    "hash",
		IPAddress:           "127.0.0.1",
		UserAgent:           "test",
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
		&mockSessionRepo{},
		&mockClientRepo{valid: true, exists: true},
	)

	in := &IssueCodeInput{
		ResponseType:        "code",
		UserID:              uuid.New(),
		ClientID:            uuid.New(),
		RedirectURI:         "https://example.com/callback",
		Scopes:              "openid",
		State:               "xyz",
		Nonce:               "",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "plain",
		SessionTokenHash:    "hash",
		IPAddress:           "127.0.0.1",
		UserAgent:           "test",
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
		&mockSessionRepo{},
		&mockClientRepo{valid: false, exists: true},
	)

	in := &IssueCodeInput{
		ResponseType:        "code",
		UserID:              uuid.New(),
		ClientID:            uuid.New(),
		RedirectURI:         "https://evil.com/callback",
		Scopes:              "openid",
		State:               "xyz",
		Nonce:               "",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: authcode.CodeChallengeMethodS256,
		SessionTokenHash:    "hash",
		IPAddress:           "127.0.0.1",
		UserAgent:           "test",
	}

	_, err := uc.IssueCode(context.Background(), in)
	if err == nil {
		t.Fatal("IssueCode: expected error for invalid redirect_uri")
	}
	if !errors.Is(err, ErrInvalidRedirectURI) {
		t.Errorf("IssueCode: expected ErrInvalidRedirectURI, got %v", err)
	}
}

func TestUseCase_IssueCode_UseExistingSession(t *testing.T) {
	userID := uuid.New()
	existingSession := session.New(
		userID,
		"hash",
		"127.0.0.1",
		"Mozilla",
		1,
		time.Now().Add(time.Hour),
	)

	uc := NewUseCase(
		&mockAuthCodeRepo{},
		&mockSessionRepo{findBySessionToken: existingSession},
		&mockClientRepo{valid: true, exists: true},
	)

	in := &IssueCodeInput{
		ResponseType:        "code",
		UserID:              userID,
		ClientID:            uuid.New(),
		RedirectURI:         "https://example.com/callback",
		Scopes:              "openid",
		State:               "xyz",
		Nonce:               "n-456",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: authcode.CodeChallengeMethodS256,
		SessionTokenHash:    "hash",
		IPAddress:           "127.0.0.1",
		UserAgent:           "test",
	}

	out, err := uc.IssueCode(context.Background(), in)
	if err != nil {
		t.Fatalf("IssueCode: unexpected error: %v", err)
	}
	if out.Code == "" {
		t.Error("IssueCode: expected non-empty code")
	}
}
