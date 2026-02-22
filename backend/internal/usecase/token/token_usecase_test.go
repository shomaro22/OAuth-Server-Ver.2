package token

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/authcode"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/session"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/token"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/port"
)

type mockTxRunner struct{}

func (m *mockTxRunner) Transaction(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

type mockAuthCodeRepo struct {
	code             *authcode.AuthorizationCode
	err              error
	markConsumedRows *int64 // nil=1, 0=rows affected 0 をシミュレート
}

func (m *mockAuthCodeRepo) Save(ctx context.Context, code *authcode.AuthorizationCode) error {
	return nil
}

func (m *mockAuthCodeRepo) FindByCodeHash(ctx context.Context, codeHash string) (*authcode.AuthorizationCode, error) {
	return m.code, m.err
}

func (m *mockAuthCodeRepo) FindByCodeHashForUpdate(ctx context.Context, codeHash string) (*authcode.AuthorizationCode, error) {
	return m.code, m.err
}

func (m *mockAuthCodeRepo) MarkConsumed(ctx context.Context, id uuid.UUID) (int64, error) {
	if m.code == nil {
		return 0, nil
	}
	if m.markConsumedRows != nil && *m.markConsumedRows == 0 {
		return 0, nil
	}
	return 1, nil
}

func (m *mockAuthCodeRepo) Delete(ctx context.Context, id uuid.UUID) error {
	return nil
}

type mockTokenRepo struct {
	accessTokenID         uuid.UUID
	err                   error
	saveAccessTokenErr    error
	saveRefreshTokenErr   error
	refreshToken          *token.RefreshToken
	accessTokenForRefresh *token.AccessToken
	markRotatedCalled     int
	revokeATCalled        int
}

func (m *mockTokenRepo) SaveAccessToken(ctx context.Context, userID, clientID, sessionID uuid.UUID, tokenJTI, scopes string, expiresAt time.Time) (uuid.UUID, error) {
	if m.saveAccessTokenErr != nil {
		return uuid.Nil, m.saveAccessTokenErr
	}
	return m.accessTokenID, m.err
}

func (m *mockTokenRepo) SaveRefreshToken(ctx context.Context, accessTokenID uuid.UUID, tokenHash string, expiresAt time.Time) (uuid.UUID, error) {
	if m.saveRefreshTokenErr != nil {
		return uuid.Nil, m.saveRefreshTokenErr
	}
	return uuid.New(), m.err
}

func (m *mockTokenRepo) FindAccessTokenByJTI(ctx context.Context, tokenJTI string) (*token.AccessToken, error) {
	return nil, nil
}

func (m *mockTokenRepo) FindAccessTokenByID(ctx context.Context, id uuid.UUID) (*token.AccessToken, error) {
	if m.accessTokenForRefresh != nil {
		return m.accessTokenForRefresh, m.err
	}
	uid := uuid.New()
	cid := uuid.New()
	sid := uuid.New()
	return token.NewAccessToken(id, uid, cid, sid, "", "openid", time.Now(), time.Now().Add(time.Hour), false), m.err
}

func (m *mockTokenRepo) FindRefreshTokenByHash(ctx context.Context, tokenHash string) (*token.RefreshToken, error) {
	if m.refreshToken != nil {
		return m.refreshToken, m.err
	}
	return token.NewRefreshToken(uuid.New(), m.accessTokenID, "", time.Now().Add(time.Hour), false, false), m.err
}


func (m *mockTokenRepo) RevokeAccessToken(ctx context.Context, id uuid.UUID) error {
	m.revokeATCalled++
	return nil
}

func (m *mockTokenRepo) RevokeRefreshToken(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockTokenRepo) MarkRefreshTokenRotated(ctx context.Context, id uuid.UUID) error {
	m.markRotatedCalled++
	return nil
}

type mockClientRepo struct {
	exists bool
	valid  bool
}

func (m *mockClientRepo) Exists(ctx context.Context, clientID uuid.UUID) (bool, error) {
	return m.exists, nil
}

func (m *mockClientRepo) ValidateRedirectURI(ctx context.Context, clientID uuid.UUID, redirectURI string) (bool, error) {
	return m.valid, nil
}

func (m *mockClientRepo) ValidateClientCredentials(ctx context.Context, clientID uuid.UUID, clientSecret string) (bool, error) {
	return false, nil
}

func (m *mockClientRepo) GetAllowedScopes(ctx context.Context, clientID uuid.UUID) ([]string, error) {
	return []string{"openid", "profile", "email"}, nil
}

type mockJWTSigner struct {
	signErr       error
	signIDTokenErr error
}

func (m *mockJWTSigner) Sign(sub, sid, aud uuid.UUID, ver int64, jti string, expiresIn time.Duration) (string, error) {
	if m != nil && m.signErr != nil {
		return "", m.signErr
	}
	return "mock-jwt", nil
}

func (m *mockJWTSigner) SignIDToken(iss, sub, aud string, nonce string, authTime time.Time, expiresIn time.Duration) (string, error) {
	if m != nil && m.signIDTokenErr != nil {
		return "", m.signIDTokenErr
	}
	return "mock-id-token", nil
}

func (m *mockJWTSigner) Verify(tokenString string) (*port.AccessTokenClaims, error) {
	return nil, nil
}

type mockSessionRepo struct {
	findByID       *session.Session
	sessionNotFound bool // true のとき FindByID が (nil, nil) を返す
	incCalled      int
	revokeCalled   int
}

func (m *mockSessionRepo) Save(ctx context.Context, s *session.Session) error { return nil }
func (m *mockSessionRepo) FindByID(ctx context.Context, sid uuid.UUID) (*session.Session, error) {
	if m.sessionNotFound {
		return nil, nil
	}
	if m.findByID != nil {
		return m.findByID, nil
	}
	return session.New(uuid.New(), "hash", "127.0.0.1", "test", 1, time.Now().Add(time.Hour)), nil
}
func (m *mockSessionRepo) FindBySessionTokenHash(ctx context.Context, tokenHash string) (*session.Session, error) {
	return nil, nil
}
func (m *mockSessionRepo) IncrementTokenVersion(ctx context.Context, sid uuid.UUID) error {
	m.incCalled++
	return nil
}
func (m *mockSessionRepo) Revoke(ctx context.Context, sid uuid.UUID) error {
	m.revokeCalled++
	return nil
}

func TestUseCase_Exchange_InvalidCode(t *testing.T) {
	uc := NewUseCase(
		&mockTxRunner{},
		&mockAuthCodeRepo{code: nil, err: nil},
		&mockTokenRepo{},
		&mockClientRepo{exists: true, valid: true},
		&mockSessionRepo{findByID: nil},
		&mockJWTSigner{},
		"https://test",
	)

	_, err := uc.Exchange(context.Background(), &ExchangeInput{
		Code:         "invalid",
		RedirectURI:  "https://example.com/cb",
		ClientID:     uuid.New(),
		CodeVerifier: "verifier",
	})
	if err != ErrInvalidCode {
		t.Errorf("expected ErrInvalidCode, got %v", err)
	}
}

// TestUseCase_Exchange_CodeReuse は code 再利用時に invalid_grant 相当（ErrInvalidCode）を返す。
func TestUseCase_Exchange_CodeReuse(t *testing.T) {
	clientID := uuid.New()
	codeHash := hashStr("some-code")
	challenge := computeChallengeS256("verifier")

	consumedCode := authcode.Reconstruct(
		uuid.New(), uuid.New(), clientID, uuid.New(),
		codeHash, challenge, authcode.CodeChallengeMethodS256,
		"https://example.com/cb", "openid", "nonce",
		time.Now().Add(10*time.Minute), true, time.Now(),
	)

	uc := NewUseCase(
		&mockTxRunner{},
		&mockAuthCodeRepo{code: consumedCode, err: nil},
		&mockTokenRepo{},
		&mockClientRepo{exists: true, valid: true},
		&mockSessionRepo{findByID: nil},
		&mockJWTSigner{},
		"https://test",
	)

	_, err := uc.Exchange(context.Background(), &ExchangeInput{
		Code:         "some-code",
		RedirectURI:  "https://example.com/cb",
		ClientID:     clientID,
		CodeVerifier: "verifier",
	})
	if err != ErrInvalidCode {
		t.Errorf("code reuse: expected ErrInvalidCode, got %v", err)
	}
}

// TestUseCase_Exchange_CodeVerifierEmpty は code_challenge ありで code_verifier 空のとき ErrInvalidPKCE を返す。
func TestUseCase_Exchange_CodeVerifierEmpty(t *testing.T) {
	clientID := uuid.New()
	codeHash := hashStr("some-code")
	challenge := computeChallengeS256("verifier")

	validCode := authcode.Reconstruct(
		uuid.New(), uuid.New(), clientID, uuid.New(),
		codeHash, challenge, authcode.CodeChallengeMethodS256,
		"https://example.com/cb", "openid", "nonce",
		time.Now().Add(10*time.Minute), false, time.Now(),
	)

	uc := NewUseCase(
		&mockTxRunner{},
		&mockAuthCodeRepo{code: validCode, err: nil},
		&mockTokenRepo{},
		&mockClientRepo{exists: true, valid: true},
		&mockSessionRepo{findByID: nil},
		&mockJWTSigner{},
		"https://test",
	)

	_, err := uc.Exchange(context.Background(), &ExchangeInput{
		Code:         "some-code",
		RedirectURI:  "https://example.com/cb",
		ClientID:     clientID,
		CodeVerifier: "", // 空
	})
	if err != ErrInvalidPKCE {
		t.Errorf("expected ErrInvalidPKCE, got %v", err)
	}
}

// TestUseCase_Exchange_CodeChallengeMethodNotS256 は method != S256 のとき ErrInvalidPKCE を返す。
func TestUseCase_Exchange_CodeChallengeMethodNotS256(t *testing.T) {
	clientID := uuid.New()
	codeHash := hashStr("some-code")

	validCode := authcode.Reconstruct(
		uuid.New(), uuid.New(), clientID, uuid.New(),
		codeHash, "challenge", "plain", // plain は非サポート
		"https://example.com/cb", "openid", "nonce",
		time.Now().Add(10*time.Minute), false, time.Now(),
	)

	uc := NewUseCase(
		&mockTxRunner{},
		&mockAuthCodeRepo{code: validCode, err: nil},
		&mockTokenRepo{},
		&mockClientRepo{exists: true, valid: true},
		&mockSessionRepo{findByID: nil},
		&mockJWTSigner{},
		"https://test",
	)

	_, err := uc.Exchange(context.Background(), &ExchangeInput{
		Code:         "some-code",
		RedirectURI:  "https://example.com/cb",
		ClientID:     clientID,
		CodeVerifier: "verifier",
	})
	if err != ErrInvalidPKCE {
		t.Errorf("expected ErrInvalidPKCE, got %v", err)
	}
}

// TestUseCase_Exchange_MarkConsumedRowsZero は MarkConsumed が 0 行のとき ErrInvalidCode を返す。
func TestUseCase_Exchange_MarkConsumedRowsZero(t *testing.T) {
	clientID := uuid.New()
	codeHash := hashStr("some-code")
	challenge := computeChallengeS256("verifier")
	zero := int64(0)

	validCode := authcode.Reconstruct(
		uuid.New(), uuid.New(), clientID, uuid.New(),
		codeHash, challenge, authcode.CodeChallengeMethodS256,
		"https://example.com/cb", "openid", "nonce",
		time.Now().Add(10*time.Minute), false, time.Now(),
	)

	uc := NewUseCase(
		&mockTxRunner{},
		&mockAuthCodeRepo{code: validCode, markConsumedRows: &zero},
		&mockTokenRepo{},
		&mockClientRepo{exists: true, valid: true},
		&mockSessionRepo{findByID: nil},
		&mockJWTSigner{},
		"https://test",
	)

	_, err := uc.Exchange(context.Background(), &ExchangeInput{
		Code:         "some-code",
		RedirectURI:  "https://example.com/cb",
		ClientID:     clientID,
		CodeVerifier: "verifier",
	})
	if err != ErrInvalidCode {
		t.Errorf("expected ErrInvalidCode, got %v", err)
	}
}

// TestUseCase_Exchange_PKCEMismatch は PKCE verifier 不一致時に invalid_grant 相当（ErrInvalidPKCE）を返す。
func TestUseCase_Exchange_PKCEMismatch(t *testing.T) {
	clientID := uuid.New()
	codeHash := hashStr("some-code")
	challenge := computeChallengeS256("correct-verifier")

	validCode := authcode.Reconstruct(
		uuid.New(), uuid.New(), clientID, uuid.New(),
		codeHash, challenge, authcode.CodeChallengeMethodS256,
		"https://example.com/cb", "openid", "nonce",
		time.Now().Add(10*time.Minute), false, time.Now(),
	)

	uc := NewUseCase(
		&mockTxRunner{},
		&mockAuthCodeRepo{code: validCode, err: nil},
		&mockTokenRepo{},
		&mockClientRepo{exists: true, valid: true},
		&mockSessionRepo{findByID: nil},
		&mockJWTSigner{},
		"https://test",
	)

	_, err := uc.Exchange(context.Background(), &ExchangeInput{
		Code:         "some-code",
		RedirectURI:  "https://example.com/cb",
		ClientID:     clientID,
		CodeVerifier: "wrong-verifier",
	})
	if err != ErrInvalidPKCE {
		t.Errorf("PKCE mismatch: expected ErrInvalidPKCE, got %v", err)
	}
}

// TestUseCase_Exchange_InvalidClient は client が存在しない場合に ErrInvalidClient を返す。
func TestUseCase_Exchange_InvalidClient(t *testing.T) {
	uc := NewUseCase(
		&mockTxRunner{},
		&mockAuthCodeRepo{code: nil, err: nil},
		&mockTokenRepo{},
		&mockClientRepo{exists: false, valid: true},
		&mockSessionRepo{},
		&mockJWTSigner{},
		"https://test",
	)

	_, err := uc.Exchange(context.Background(), &ExchangeInput{
		Code:         "any",
		RedirectURI:  "https://example.com/cb",
		ClientID:     uuid.New(),
		CodeVerifier: "v",
	})
	if err != ErrInvalidClient {
		t.Errorf("expected ErrInvalidClient, got %v", err)
	}
}

// TestUseCase_Exchange_InvalidRedirectURI は redirect_uri 不一致時に ErrInvalidRedirectURI を返す。
func TestUseCase_Exchange_InvalidRedirectURI(t *testing.T) {
	uc := NewUseCase(
		&mockTxRunner{},
		&mockAuthCodeRepo{code: nil, err: nil},
		&mockTokenRepo{},
		&mockClientRepo{exists: true, valid: false},
		&mockSessionRepo{},
		&mockJWTSigner{},
		"https://test",
	)

	_, err := uc.Exchange(context.Background(), &ExchangeInput{
		Code:         "any",
		RedirectURI:  "https://evil.com/cb",
		ClientID:     uuid.New(),
		CodeVerifier: "v",
	})
	if err != ErrInvalidRedirectURI {
		t.Errorf("expected ErrInvalidRedirectURI, got %v", err)
	}
}

// TestUseCase_Refresh_NotFound は refresh token が存在しない場合に ErrInvalidRefreshToken を返す。
func TestUseCase_Refresh_NotFound(t *testing.T) {
	repo := &mockTokenRepo{refreshToken: nil}
	uc := NewUseCase(&mockTxRunner{}, &mockAuthCodeRepo{}, repo, &mockClientRepo{}, &mockSessionRepo{}, &mockJWTSigner{}, "https://test")

	_, err := uc.Refresh(context.Background(), &RefreshInput{RefreshToken: "any", ClientID: uuid.New()})
	if err != ErrInvalidRefreshToken {
		t.Errorf("expected ErrInvalidRefreshToken, got %v", err)
	}
}

// TestUseCase_Refresh_Revoked は revoked な refresh token で ErrInvalidRefreshToken を返す。
func TestUseCase_Refresh_Revoked(t *testing.T) {
	rt := token.NewRefreshToken(uuid.New(), uuid.New(), "hash", time.Now().Add(time.Hour), true, false)
	repo := &mockTokenRepo{refreshToken: rt}
	uc := NewUseCase(&mockTxRunner{}, &mockAuthCodeRepo{}, repo, &mockClientRepo{}, &mockSessionRepo{}, &mockJWTSigner{}, "https://test")

	_, err := uc.Refresh(context.Background(), &RefreshInput{RefreshToken: "any", ClientID: uuid.New()})
	if err != ErrInvalidRefreshToken {
		t.Errorf("expected ErrInvalidRefreshToken, got %v", err)
	}
}

// TestUseCase_Refresh_Rotated は再利用（rotated）検知で ErrInvalidRefreshToken を返す。
func TestUseCase_Refresh_Rotated(t *testing.T) {
	rt := token.NewRefreshToken(uuid.New(), uuid.New(), "hash", time.Now().Add(time.Hour), false, true)
	repo := &mockTokenRepo{refreshToken: rt}
	uc := NewUseCase(&mockTxRunner{}, &mockAuthCodeRepo{}, repo, &mockClientRepo{}, &mockSessionRepo{}, &mockJWTSigner{}, "https://test")

	_, err := uc.Refresh(context.Background(), &RefreshInput{RefreshToken: "any", ClientID: uuid.New()})
	if err != ErrInvalidRefreshToken {
		t.Errorf("expected ErrInvalidRefreshToken (rotated), got %v", err)
	}
}

// TestUseCase_Refresh_ClientIDMismatch は client_id 不一致で ErrInvalidRefreshToken を返す。
func TestUseCase_Refresh_ClientIDMismatch(t *testing.T) {
	clientID := uuid.New()
	otherClientID := uuid.New()
	at := token.NewAccessToken(uuid.New(), uuid.New(), otherClientID, uuid.New(), "jti", "openid", time.Now(), time.Now().Add(time.Hour), false)
	rt := token.NewRefreshToken(uuid.New(), at.ID(), "hash", time.Now().Add(time.Hour), false, false)

	repo := &mockTokenRepo{refreshToken: rt, accessTokenForRefresh: at}
	uc := NewUseCase(&mockTxRunner{}, &mockAuthCodeRepo{}, repo, &mockClientRepo{}, &mockSessionRepo{}, &mockJWTSigner{}, "https://test")

	_, err := uc.Refresh(context.Background(), &RefreshInput{RefreshToken: "any", ClientID: clientID})
	if err != ErrInvalidRefreshToken {
		t.Errorf("expected ErrInvalidRefreshToken (client mismatch), got %v", err)
	}
}

// TestUseCase_Refresh_Success は issueTokens を通して access_token / id_token を返す。
func TestUseCase_Refresh_Success(t *testing.T) {
	clientID := uuid.New()
	userID := uuid.New()
	sid := uuid.New()
	atID := uuid.New()

	at := token.NewAccessToken(atID, userID, clientID, sid, "jti", "openid", time.Now(), time.Now().Add(time.Hour), false)
	rt := token.NewRefreshToken(uuid.New(), atID, "hash", time.Now().Add(24*time.Hour), false, false)
	sess := session.New(sid, "hash", "127.0.0.1", "test", 1, time.Now().Add(time.Hour))

	repo := &mockTokenRepo{refreshToken: rt, accessTokenForRefresh: at}
	uc := NewUseCase(&mockTxRunner{}, &mockAuthCodeRepo{}, repo, &mockClientRepo{}, &mockSessionRepo{findByID: sess}, &mockJWTSigner{}, "https://issuer.test")

	out, err := uc.Refresh(context.Background(), &RefreshInput{RefreshToken: "any", ClientID: clientID})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if out.AccessToken == "" || out.RefreshToken == "" || out.IDToken == "" {
		t.Errorf("Refresh: expected tokens, got access=%q refresh=%q id_token=%q", out.AccessToken, out.RefreshToken, out.IDToken)
	}
	if out.TokenType != "Bearer" || out.ExpiresIn != 300 {
		t.Errorf("Refresh: TokenType=%s ExpiresIn=%d", out.TokenType, out.ExpiresIn)
	}
	// 副作用検証
	if repo.markRotatedCalled != 1 {
		t.Errorf("MarkRefreshTokenRotated: want 1 call, got %d", repo.markRotatedCalled)
	}
	if repo.revokeATCalled != 1 {
		t.Errorf("RevokeAccessToken: want 1 call, got %d", repo.revokeATCalled)
	}
}

// TestUseCase_Refresh_Expired は refresh token 期限切れで ErrTokenExpired を返す。
func TestUseCase_Refresh_Expired(t *testing.T) {
	clientID := uuid.New()
	atID := uuid.New()
	at := token.NewAccessToken(atID, uuid.New(), clientID, uuid.New(), "jti", "openid", time.Now(), time.Now().Add(time.Hour), false)
	rt := token.NewRefreshToken(uuid.New(), atID, "hash", time.Now().Add(-time.Hour), false, false) // 期限切れ

	repo := &mockTokenRepo{refreshToken: rt, accessTokenForRefresh: at}
	uc := NewUseCase(&mockTxRunner{}, &mockAuthCodeRepo{}, repo, &mockClientRepo{}, &mockSessionRepo{}, &mockJWTSigner{}, "https://test")

	_, err := uc.Refresh(context.Background(), &RefreshInput{RefreshToken: "any", ClientID: clientID})
	if err != ErrTokenExpired {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

// TestUseCase_Refresh_Rotated_SessionRevoked は rotated 検知時に sessionRepo.IncrementTokenVersion と Revoke が呼ばれることを検証。
func TestUseCase_Refresh_Rotated_SessionRevoked(t *testing.T) {
	clientID := uuid.New()
	sid := uuid.New()
	atID := uuid.New()
	at := token.NewAccessToken(atID, uuid.New(), clientID, sid, "jti", "openid", time.Now(), time.Now().Add(time.Hour), false)
	rt := token.NewRefreshToken(uuid.New(), atID, "hash", time.Now().Add(24*time.Hour), false, true) // rotated

	sessRepo := &mockSessionRepo{}
	repo := &mockTokenRepo{refreshToken: rt, accessTokenForRefresh: at}
	uc := NewUseCase(&mockTxRunner{}, &mockAuthCodeRepo{}, repo, &mockClientRepo{}, sessRepo, &mockJWTSigner{}, "https://test")

	_, err := uc.Refresh(context.Background(), &RefreshInput{RefreshToken: "any", ClientID: clientID})
	if err != ErrInvalidRefreshToken {
		t.Errorf("expected ErrInvalidRefreshToken (rotated), got %v", err)
	}
	if sessRepo.incCalled != 1 {
		t.Errorf("IncrementTokenVersion: want 1 call, got %d", sessRepo.incCalled)
	}
	if sessRepo.revokeCalled != 1 {
		t.Errorf("Revoke: want 1 call, got %d", sessRepo.revokeCalled)
	}
}

// TestUseCase_issueTokens_SecureTokenAccessJTI_Fail は accessJTI 生成失敗でエラーを返す。
func TestUseCase_issueTokens_SecureTokenAccessJTI_Fail(t *testing.T) {
	uc := NewUseCase(&mockTxRunner{}, &mockAuthCodeRepo{}, &mockTokenRepo{}, &mockClientRepo{}, &mockSessionRepo{}, &mockJWTSigner{}, "https://test")
	uc.secureToken = func() (string, error) { return "", errors.New("rand fail") }

	_, err := uc.issueTokens(context.Background(), uuid.New(), uuid.New(), uuid.New(), "openid", "", time.Now())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "generate access token") {
		t.Errorf("expected generate access token error, got %v", err)
	}
}

// TestUseCase_issueTokens_SessionNotFound は session が見つからない場合にエラーを返す。
func TestUseCase_issueTokens_SessionNotFound(t *testing.T) {
	uc := NewUseCase(&mockTxRunner{}, &mockAuthCodeRepo{}, &mockTokenRepo{}, &mockClientRepo{}, &mockSessionRepo{sessionNotFound: true}, &mockJWTSigner{}, "https://test")
	uc.secureToken = func() (string, error) { return "jti", nil }

	_, err := uc.issueTokens(context.Background(), uuid.New(), uuid.New(), uuid.New(), "openid", "", time.Now())
	if err == nil {
		t.Fatal("expected error")
	}
}

// TestUseCase_issueTokens_JWTSignFail は JWT Sign 失敗でエラーを返す。
func TestUseCase_issueTokens_JWTSignFail(t *testing.T) {
	jwtSigner := &mockJWTSigner{signErr: errors.New("sign fail")}
	uc := NewUseCase(&mockTxRunner{}, &mockAuthCodeRepo{}, &mockTokenRepo{}, &mockClientRepo{}, &mockSessionRepo{}, jwtSigner, "https://test")
	uc.secureToken = func() (string, error) { return "jti", nil }

	_, err := uc.issueTokens(context.Background(), uuid.New(), uuid.New(), uuid.New(), "openid", "", time.Now())
	if err == nil {
		t.Fatal("expected error")
	}
}

// TestUseCase_issueTokens_SaveAccessTokenFail は SaveAccessToken 失敗でエラーを返す。
func TestUseCase_issueTokens_SaveAccessTokenFail(t *testing.T) {
	tokenRepo := &mockTokenRepo{saveAccessTokenErr: errors.New("db fail")}
	uc := NewUseCase(&mockTxRunner{}, &mockAuthCodeRepo{}, tokenRepo, &mockClientRepo{}, &mockSessionRepo{}, &mockJWTSigner{}, "https://test")
	uc.secureToken = func() (string, error) { return "jti", nil }

	_, err := uc.issueTokens(context.Background(), uuid.New(), uuid.New(), uuid.New(), "openid", "", time.Now())
	if err == nil {
		t.Fatal("expected error")
	}
}

// TestUseCase_issueTokens_SecureTokenRefresh_Fail は refresh token 生成（2回目）失敗でエラーを返す。
func TestUseCase_issueTokens_SecureTokenRefresh_Fail(t *testing.T) {
	calls := 0
	uc := NewUseCase(&mockTxRunner{}, &mockAuthCodeRepo{}, &mockTokenRepo{}, &mockClientRepo{}, &mockSessionRepo{}, &mockJWTSigner{}, "https://test")
	uc.secureToken = func() (string, error) {
		calls++
		if calls == 1 {
			return "access-jti", nil
		}
		return "", errors.New("boom")
	}

	_, err := uc.issueTokens(context.Background(), uuid.New(), uuid.New(), uuid.New(), "openid", "", time.Now())
	if err == nil {
		t.Fatal("expected error")
	}
}

// TestUseCase_issueTokens_SaveRefreshTokenFail は SaveRefreshToken 失敗でエラーを返す。
func TestUseCase_issueTokens_SaveRefreshTokenFail(t *testing.T) {
	tokenRepo := &mockTokenRepo{saveRefreshTokenErr: errors.New("db fail")}
	uc := NewUseCase(&mockTxRunner{}, &mockAuthCodeRepo{}, tokenRepo, &mockClientRepo{}, &mockSessionRepo{}, &mockJWTSigner{}, "https://test")
	uc.secureToken = func() (string, error) { return "jti", nil }

	_, err := uc.issueTokens(context.Background(), uuid.New(), uuid.New(), uuid.New(), "openid", "", time.Now())
	if err == nil {
		t.Fatal("expected error")
	}
}

func hashStr(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func computeChallengeS256(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(h[:])
}
