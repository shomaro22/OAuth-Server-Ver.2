package token

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/authcode"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/token"
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

func (m *mockTokenRepo) SaveAccessToken(ctx context.Context, userID, clientID uuid.UUID, tokenJTI, scopes string, expiresAt time.Time) (uuid.UUID, error) {
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
	return token.NewAccessToken(id, uid, cid, "", "openid", time.Now(), time.Now().Add(time.Hour), false), m.err
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

func TestUseCase_Exchange_InvalidCode(t *testing.T) {
	uc := NewUseCase(
		&mockAuthCodeRepo{code: nil, err: nil},
		&mockTokenRepo{},
		&mockClientRepo{},
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
