package userinfo

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/session"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/token"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/user"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/infrastructure/jwt"
)

type mockTokenRepo struct {
	findByJTI *token.AccessToken
	err       error
}

func (m *mockTokenRepo) SaveAccessToken(ctx context.Context, userID, clientID, sessionID uuid.UUID, tokenJTI, scopes string, expiresAt time.Time) (uuid.UUID, error) {
	return uuid.New(), nil
}
func (m *mockTokenRepo) SaveRefreshToken(ctx context.Context, accessTokenID uuid.UUID, tokenHash string, expiresAt time.Time) (uuid.UUID, error) {
	return uuid.New(), nil
}
func (m *mockTokenRepo) FindAccessTokenByJTI(ctx context.Context, tokenJTI string) (*token.AccessToken, error) {
	return m.findByJTI, m.err
}
func (m *mockTokenRepo) FindAccessTokenByID(ctx context.Context, id uuid.UUID) (*token.AccessToken, error) {
	return nil, nil
}
func (m *mockTokenRepo) FindRefreshTokenByHash(ctx context.Context, tokenHash string) (*token.RefreshToken, error) {
	return nil, nil
}
func (m *mockTokenRepo) RevokeAccessToken(ctx context.Context, id uuid.UUID) error { return nil }
func (m *mockTokenRepo) RevokeRefreshToken(ctx context.Context, id uuid.UUID) error { return nil }
func (m *mockTokenRepo) MarkRefreshTokenRotated(ctx context.Context, id uuid.UUID) error {
	return nil
}

type mockUserRepo struct {
	findByID *user.User
	err      error
}

func (m *mockUserRepo) FindByID(ctx context.Context, id uuid.UUID) (*user.User, error) {
	return m.findByID, m.err
}
func (m *mockUserRepo) FindByUsername(ctx context.Context, username string) (*user.User, string, error) {
	return nil, "", nil
}
func (m *mockUserRepo) Save(ctx context.Context, u *user.User) error { return nil }

type mockSessionRepo struct {
	findByID *session.Session
}

func (m *mockSessionRepo) Save(ctx context.Context, s *session.Session) error { return nil }
func (m *mockSessionRepo) FindByID(ctx context.Context, sid uuid.UUID) (*session.Session, error) {
	if m.findByID != nil {
		return m.findByID, nil
	}
	return nil, nil
}
func (m *mockSessionRepo) FindBySessionTokenHash(ctx context.Context, tokenHash string) (*session.Session, error) {
	return nil, nil
}
func (m *mockSessionRepo) IncrementTokenVersion(ctx context.Context, sid uuid.UUID) error { return nil }
func (m *mockSessionRepo) Revoke(ctx context.Context, sid uuid.UUID) error { return nil }

func TestUseCase_Get_InvalidToken_JWTVerifyFails(t *testing.T) {
	key, _ := jwt.GenerateKey()
	signer := jwt.NewSigner(key)

	uc := NewUseCase(
		&mockTokenRepo{},
		&mockUserRepo{},
		&mockSessionRepo{},
		signer,
	)

	_, err := uc.Get(context.Background(), &GetInput{AccessToken: "invalid.jwt.token"})
	if err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestUseCase_Get_InvalidToken_AccessTokenNotFound(t *testing.T) {
	key, _ := jwt.GenerateKey()
	signer := jwt.NewSigner(key)
	tokenStr, _ := signer.Sign(uuid.New(), uuid.New(), uuid.New(), 1, "jti-1", time.Hour)

	uc := NewUseCase(
		&mockTokenRepo{findByJTI: nil},
		&mockUserRepo{},
		&mockSessionRepo{},
		signer,
	)

	_, err := uc.Get(context.Background(), &GetInput{AccessToken: tokenStr})
	if err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestUseCase_Get_InvalidToken_AccessTokenRevoked(t *testing.T) {
	key, _ := jwt.GenerateKey()
	signer := jwt.NewSigner(key)
	sub := uuid.New()
	sid := uuid.New()
	aud := uuid.New()
	tokenStr, _ := signer.Sign(sub, sid, aud, 1, "jti-revoked", time.Hour)

	at := token.NewAccessToken(uuid.New(), sub, aud, sid, "jti-revoked", "openid", time.Now(), time.Now().Add(time.Hour), true)

	uc := NewUseCase(
		&mockTokenRepo{findByJTI: at},
		&mockUserRepo{},
		&mockSessionRepo{},
		signer,
	)

	_, err := uc.Get(context.Background(), &GetInput{AccessToken: tokenStr})
	if err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestUseCase_Get_Success(t *testing.T) {
	key, _ := jwt.GenerateKey()
	signer := jwt.NewSigner(key)
	sub := uuid.New()
	sid := uuid.New()
	aud := uuid.New()
	tokenStr, _ := signer.Sign(sub, sid, aud, 1, "jti-ok", time.Hour)

	at := token.NewAccessToken(uuid.New(), sub, aud, sid, "jti-ok", "openid", time.Now(), time.Now().Add(time.Hour), false)
	u := user.NewUser(sub, "a@b.com", "testuser", true, "active", time.Now(), time.Now())

	sess := session.New(sid, "hash", "127.0.0.1", "test", 1, time.Now().Add(time.Hour))
	uc := NewUseCase(
		&mockTokenRepo{findByJTI: at},
		&mockUserRepo{findByID: u},
		&mockSessionRepo{findByID: sess},
		signer,
	)

	out, err := uc.Get(context.Background(), &GetInput{AccessToken: tokenStr})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if out.Sub != sub.String() || out.PreferredUsername != "testuser" || out.Email != "a@b.com" {
		t.Errorf("Get: output mismatch sub=%s username=%s email=%s", out.Sub, out.PreferredUsername, out.Email)
	}
}

