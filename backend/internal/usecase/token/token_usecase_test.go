package token

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/authcode"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/session"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/token"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/port"
)

type mockAuthCodeRepo struct {
	code *authcode.AuthorizationCode
	err  error
}

func (m *mockAuthCodeRepo) Save(ctx context.Context, code *authcode.AuthorizationCode) error {
	return nil
}

func (m *mockAuthCodeRepo) FindByCodeHash(ctx context.Context, codeHash string) (*authcode.AuthorizationCode, error) {
	return m.code, m.err
}

func (m *mockAuthCodeRepo) MarkConsumed(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockAuthCodeRepo) Delete(ctx context.Context, id uuid.UUID) error {
	return nil
}

type mockTokenRepo struct {
	accessTokenID uuid.UUID
	err           error
}

func (m *mockTokenRepo) SaveAccessToken(ctx context.Context, userID, clientID, sessionID uuid.UUID, tokenJTI, scopes string, expiresAt time.Time) (uuid.UUID, error) {
	return m.accessTokenID, m.err
}

func (m *mockTokenRepo) SaveRefreshToken(ctx context.Context, accessTokenID uuid.UUID, tokenHash string, expiresAt time.Time) (uuid.UUID, error) {
	return uuid.New(), m.err
}

func (m *mockTokenRepo) FindAccessTokenByJTI(ctx context.Context, tokenJTI string) (*token.AccessToken, error) {
	return nil, nil
}

func (m *mockTokenRepo) FindAccessTokenByID(ctx context.Context, id uuid.UUID) (*token.AccessToken, error) {
	uid := uuid.New()
	cid := uuid.New()
	sid := uuid.New()
	return token.NewAccessToken(id, uid, cid, sid, "", "openid", time.Now(), time.Now().Add(time.Hour), false), m.err
}

func (m *mockTokenRepo) FindRefreshTokenByHash(ctx context.Context, tokenHash string) (*token.RefreshToken, error) {
	return token.NewRefreshToken(uuid.New(), m.accessTokenID, "", time.Now().Add(time.Hour), false, false), m.err
}

func (m *mockTokenRepo) RevokeAccessToken(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockTokenRepo) RevokeRefreshToken(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockTokenRepo) MarkRefreshTokenRotated(ctx context.Context, id uuid.UUID) error {
	return nil
}

type mockClientRepo struct {
	valid bool
}

func (m *mockClientRepo) ValidateRedirectURI(ctx context.Context, clientID uuid.UUID, redirectURI string) (bool, error) {
	return m.valid, nil
}

type mockJWTSigner struct{}

func (m *mockJWTSigner) Sign(sub, sid, aud uuid.UUID, ver int64, jti string, expiresIn time.Duration) (string, error) {
	return "mock-jwt", nil
}
func (m *mockJWTSigner) Verify(tokenString string) (*port.AccessTokenClaims, error) {
	return nil, nil
}

type mockSessionRepo struct {
	findByID *session.Session
}

func (m *mockSessionRepo) Save(ctx context.Context, s *session.Session) error { return nil }
func (m *mockSessionRepo) FindByID(ctx context.Context, sid uuid.UUID) (*session.Session, error) {
	if m.findByID != nil {
		return m.findByID, nil
	}
	return session.New(uuid.New(), "hash", "127.0.0.1", "test", 1, time.Now().Add(time.Hour)), nil
}
func (m *mockSessionRepo) FindBySessionTokenHash(ctx context.Context, tokenHash string) (*session.Session, error) {
	return nil, nil
}
func (m *mockSessionRepo) IncrementTokenVersion(ctx context.Context, sid uuid.UUID) error { return nil }
func (m *mockSessionRepo) Revoke(ctx context.Context, sid uuid.UUID) error { return nil }

func TestUseCase_Exchange_InvalidCode(t *testing.T) {
	uc := NewUseCase(
		&mockAuthCodeRepo{code: nil, err: nil},
		&mockTokenRepo{},
		&mockClientRepo{},
		&mockSessionRepo{findByID: nil},
		&mockJWTSigner{},
	)

	_, err := uc.Exchange(context.Background(), &ExchangeInput{
		Code:        "invalid",
		RedirectURI: "https://example.com/cb",
		ClientID:    uuid.New(),
	})
	if err != ErrInvalidCode {
		t.Errorf("expected ErrInvalidCode, got %v", err)
	}
}
