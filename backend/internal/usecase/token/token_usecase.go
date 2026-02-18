package token

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/authcode"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/port"
)

// アクセストークン有効期限（1時間）
const accessTokenExpiryMinutes = 60

// リフレッシュトークン有効期限（30日）
const refreshTokenExpiryDays = 30

var (
	ErrInvalidCode         = errors.New("invalid authorization code")
	ErrInvalidRedirectURI  = errors.New("redirect_uri mismatch")
	ErrInvalidPKCE         = errors.New("invalid code_verifier")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrTokenExpired         = errors.New("token expired")
)

// UseCase はトークン発行・更新のユースケース。
type UseCase struct {
	authCodeRepo port.AuthCodeRepository
	tokenRepo    port.TokenRepository
	clientRepo   port.ClientRepository
	sessionRepo  port.SessionRepository
	jwtSigner    port.JWTSigner
}

// NewUseCase は UseCase を生成する。
func NewUseCase(
	authCodeRepo port.AuthCodeRepository,
	tokenRepo port.TokenRepository,
	clientRepo port.ClientRepository,
	sessionRepo port.SessionRepository,
	jwtSigner port.JWTSigner,
) *UseCase {
	return &UseCase{
		authCodeRepo: authCodeRepo,
		tokenRepo:    tokenRepo,
		clientRepo:   clientRepo,
		sessionRepo:  sessionRepo,
		jwtSigner:    jwtSigner,
	}
}

// ExchangeInput は認可コード交換の入力。
type ExchangeInput struct {
	Code         string
	RedirectURI  string
	ClientID     uuid.UUID
	CodeVerifier string
}

// TokenOutput はトークン発行の出力。
type TokenOutput struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int
	RefreshToken string
	Scope        string
}

// Exchange は認可コードをトークンに交換する。
func (u *UseCase) Exchange(ctx context.Context, in *ExchangeInput) (*TokenOutput, error) {
	// 1. 認可コードを取得
	codeHash := hashString(in.Code)
	authCodeEntity, err := u.authCodeRepo.FindByCodeHash(ctx, codeHash)
	if err != nil || authCodeEntity == nil {
		return nil, ErrInvalidCode
	}

	// 2. 有効性チェック
	now := time.Now()
	if !authCodeEntity.IsValid(now) {
		return nil, ErrInvalidCode
	}

	// 3. redirect_uri 一致
	if authCodeEntity.RedirectURI() != in.RedirectURI {
		return nil, ErrInvalidRedirectURI
	}

	// 4. client_id 一致
	if authCodeEntity.ClientID() != in.ClientID {
		return nil, ErrInvalidCode
	}

	// 5. PKCE 検証（S256 のみ、code_challenge がある場合は必須）
	if authCodeEntity.CodeChallenge() != "" {
		if authCodeEntity.CodeChallengeMethod() != authcode.CodeChallengeMethodS256 {
			return nil, ErrInvalidPKCE
		}
		expectedChallenge := computeCodeChallengeS256(in.CodeVerifier)
		if expectedChallenge != authCodeEntity.CodeChallenge() {
			return nil, ErrInvalidPKCE
		}
	}

	// 6. 認可コードを消費
	if err := u.authCodeRepo.MarkConsumed(ctx, authCodeEntity.ID()); err != nil {
		return nil, fmt.Errorf("mark code consumed: %w", err)
	}

	// 7. トークン発行（session_id を渡して JWT に sid/ver を入れる準備）
	return u.issueTokens(ctx, authCodeEntity.UserID(), authCodeEntity.ClientID(), authCodeEntity.SessionID(), authCodeEntity.Scopes())
}

// RefreshInput はリフレッシュトークン交換の入力。
type RefreshInput struct {
	RefreshToken string
	ClientID     uuid.UUID
}

// Refresh はリフレッシュトークンで新しいトークンを発行する。
func (u *UseCase) Refresh(ctx context.Context, in *RefreshInput) (*TokenOutput, error) {
	// 1. リフレッシュトークンを取得
	tokenHash := hashString(in.RefreshToken)
	refreshToken, err := u.tokenRepo.FindRefreshTokenByHash(ctx, tokenHash)
	if err != nil || refreshToken == nil {
		return nil, ErrInvalidRefreshToken
	}

	if refreshToken.Revoked() {
		return nil, ErrInvalidRefreshToken
	}

	// 再利用検知（rotated 済み＝盗難の可能性）
	if refreshToken.Rotated() {
		accessToken, _ := u.tokenRepo.FindAccessTokenByID(ctx, refreshToken.AccessTokenID())
		if accessToken != nil && accessToken.SessionID() != uuid.Nil {
			sid := accessToken.SessionID()
			_ = u.sessionRepo.IncrementTokenVersion(ctx, sid)
			_ = u.sessionRepo.Revoke(ctx, sid) // 疑わしい＝セッション強制失効
		}
		return nil, ErrInvalidRefreshToken
	}

	if time.Now().After(refreshToken.ExpiresAt()) {
		return nil, ErrTokenExpired
	}

	// 2. アクセストークンを取得して user_id, client_id, scopes を取得
	accessToken, err := u.tokenRepo.FindAccessTokenByID(ctx, refreshToken.AccessTokenID())
	if err != nil || accessToken == nil {
		return nil, ErrInvalidRefreshToken
	}

	// 3. client_id 一致
	if accessToken.ClientID() != in.ClientID {
		return nil, ErrInvalidRefreshToken
	}

	// 4. リフレッシュトークンをローテーション（旧トークン失効）
	if err := u.tokenRepo.MarkRefreshTokenRotated(ctx, refreshToken.ID()); err != nil {
		return nil, fmt.Errorf("mark refresh token rotated: %w", err)
	}

	// 5. 旧アクセストークン失効
	if err := u.tokenRepo.RevokeAccessToken(ctx, accessToken.ID()); err != nil {
		return nil, fmt.Errorf("revoke access token: %w", err)
	}

	// 6. 新トークン発行（session_id を引き継ぐ）
	return u.issueTokens(ctx, accessToken.UserID(), accessToken.ClientID(), accessToken.SessionID(), accessToken.Scopes())
}

// issueTokens はアクセストークン（RS256 JWT）とリフレッシュトークンを発行する。
func (u *UseCase) issueTokens(ctx context.Context, userID, clientID, sessionID uuid.UUID, scopes string) (*TokenOutput, error) {
	accessJTI, err := generateSecureToken()
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	// token_version を取得（JWT claims に含める）
	sess, err := u.sessionRepo.FindByID(ctx, sessionID)
	if err != nil || sess == nil {
		return nil, fmt.Errorf("session not found: %w", err)
	}

	expiresIn := accessTokenExpiryMinutes * time.Minute
	jwtString, err := u.jwtSigner.Sign(userID, sessionID, clientID, sess.TokenVersion(), accessJTI, expiresIn)
	if err != nil {
		return nil, fmt.Errorf("sign jwt: %w", err)
	}

	expiresAt := time.Now().Add(expiresIn)
	accessTokenID, err := u.tokenRepo.SaveAccessToken(ctx, userID, clientID, sessionID, accessJTI, scopes, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("save access token: %w", err)
	}

	refreshToken, err := generateSecureToken()
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}
	refreshHash := hashString(refreshToken)

	refreshExpiresAt := time.Now().Add(refreshTokenExpiryDays * 24 * time.Hour)
	_, err = u.tokenRepo.SaveRefreshToken(ctx, accessTokenID, refreshHash, refreshExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("save refresh token: %w", err)
	}

	return &TokenOutput{
		AccessToken:  jwtString,
		TokenType:    "Bearer",
		ExpiresIn:    accessTokenExpiryMinutes * 60,
		RefreshToken: refreshToken,
		Scope:        scopes,
	}, nil
}

func hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func computeCodeChallengeS256(verifier string) string {
	// S256: BASE64URL(SHA256(verifier))
	h := sha256.Sum256([]byte(verifier))
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(h[:])
}

func generateSecureToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b), nil
}
