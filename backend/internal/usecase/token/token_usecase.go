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

// アクセストークン有効期限（300秒）
const accessTokenExpirySeconds = 300

// リフレッシュトークン有効期限（30日）
const refreshTokenExpiryDays = 30

// ID Token 有効期限（access_token と同程度）
const idTokenExpirySeconds = 300

var (
	ErrInvalidCode         = errors.New("invalid authorization code")
	ErrInvalidClient       = errors.New("invalid client")
	ErrInvalidRedirectURI  = errors.New("redirect_uri mismatch")
	ErrInvalidPKCE         = errors.New("invalid code_verifier")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrTokenExpired        = errors.New("token expired")
)

// UseCase はトークン発行・更新のユースケース。
// Interactor を実装する。
var _ Interactor = (*UseCase)(nil)

type UseCase struct {
	txRunner     port.TransactionRunner
	authCodeRepo port.AuthCodeRepository
	tokenRepo    port.TokenRepository
	clientRepo   port.ClientRepository
	sessionRepo  port.SessionRepository
	jwtSigner    port.JWTSigner
	issuer       string

	secureToken func() (string, error) // テスト用に差し替え可能（デフォルト: generateSecureToken）
}

// NewUseCase は UseCase を生成する。
func NewUseCase(
	txRunner port.TransactionRunner,
	authCodeRepo port.AuthCodeRepository,
	tokenRepo port.TokenRepository,
	clientRepo port.ClientRepository,
	sessionRepo port.SessionRepository,
	jwtSigner port.JWTSigner,
	issuer string,
) *UseCase {
	return &UseCase{
		txRunner:     txRunner,
		authCodeRepo: authCodeRepo,
		tokenRepo:    tokenRepo,
		clientRepo:   clientRepo,
		sessionRepo:  sessionRepo,
		jwtSigner:    jwtSigner,
		issuer:       issuer,
		secureToken:  generateSecureToken,
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
// RefreshToken は Cookie 用に handler に渡す（JSON body には含めない）。
type TokenOutput struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int
	RefreshToken string // Cookie で返却するため handler に渡す
	Scope        string
	IDToken      string
}

// Exchange は認可コードをトークンに交換する。
// 1トランザクション内で code ロック→検証→消費→トークン発行を実行し、二重交換を防止する。
func (u *UseCase) Exchange(ctx context.Context, in *ExchangeInput) (*TokenOutput, error) {
	// A. grant_type は handler で検証済み

	// B. client 検証（最小: client_id 存在 + redirect_uri 一致）
	exists, err := u.clientRepo.Exists(ctx, in.ClientID)
	if err != nil {
		return nil, fmt.Errorf("client exists check: %w", err)
	}
	if !exists {
		return nil, ErrInvalidClient
	}
	ok, err := u.clientRepo.ValidateRedirectURI(ctx, in.ClientID, in.RedirectURI)
	if err != nil {
		return nil, fmt.Errorf("validate redirect uri: %w", err)
	}
	if !ok {
		return nil, ErrInvalidRedirectURI
	}

	var out *TokenOutput
	err = u.txRunner.Transaction(ctx, func(txCtx context.Context) error {
		// C. auth code 取得（ロック付き）
		codeHash := hashString(in.Code)
		authCodeEntity, err := u.authCodeRepo.FindByCodeHashForUpdate(txCtx, codeHash)
		if err != nil {
			return fmt.Errorf("find auth code: %w", err)
		}
		if authCodeEntity == nil {
			return ErrInvalidCode
		}

		// D. code が未使用
		if authCodeEntity.IsConsumed() {
			return ErrInvalidCode
		}

		// E. code 期限切れ
		now := time.Now()
		if authCodeEntity.IsExpired(now) {
			return ErrInvalidCode
		}

		// F. redirect_uri 一致（超重要）
		if authCodeEntity.RedirectURI() != in.RedirectURI {
			return ErrInvalidRedirectURI
		}

		// G. client_id 一致
		if authCodeEntity.ClientID() != in.ClientID {
			return ErrInvalidCode
		}

		// H. PKCE 検証（S256 only、code_challenge がある場合は code_verifier 必須）
		if authCodeEntity.CodeChallenge() != "" {
			if in.CodeVerifier == "" {
				return ErrInvalidPKCE
			}
			if authCodeEntity.CodeChallengeMethod() != authcode.CodeChallengeMethodS256 {
				return ErrInvalidPKCE
			}
			expectedChallenge := computeCodeChallengeS256(in.CodeVerifier)
			if expectedChallenge != authCodeEntity.CodeChallenge() {
				return ErrInvalidPKCE
			}
		}

		// I. code を使用済みに更新（トランザクション内）
		rowsAffected, err := u.authCodeRepo.MarkConsumed(txCtx, authCodeEntity.ID())
		if err != nil {
			return fmt.Errorf("mark consumed: %w", err)
		}
		if rowsAffected != 1 {
			return ErrInvalidCode
		}

		// J. トークン発行（session / token_version 取得、JWT、RT 保存）
		o, err := u.issueTokens(txCtx, authCodeEntity.UserID(), authCodeEntity.ClientID(), authCodeEntity.SessionID(), authCodeEntity.Scopes(), authCodeEntity.Nonce(), authCodeEntity.CreatedAt())
		if err != nil {
			return err
		}
		out = o
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
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

	// 6. 新トークン発行（session_id を引き継ぐ、refresh では nonce なし）
	return u.issueTokens(ctx, accessToken.UserID(), accessToken.ClientID(), accessToken.SessionID(), accessToken.Scopes(), "", time.Now())
}

// issueTokens はアクセストークン（RS256 JWT）、ID Token、リフレッシュトークンを発行する。
// nonce が空でない場合のみ ID Token に nonce claim を入れる。authTime は ID Token の auth_time。
func (u *UseCase) issueTokens(ctx context.Context, userID, clientID, sessionID uuid.UUID, scopes, nonce string, authTime time.Time) (*TokenOutput, error) {
	gen := u.secureToken
	if gen == nil {
		gen = generateSecureToken
	}
	accessJTI, err := gen()
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	// token_version を取得（JWT claims に含める）
	sess, err := u.sessionRepo.FindByID(ctx, sessionID)
	if err != nil || sess == nil {
		return nil, fmt.Errorf("session not found: %w", err)
	}

	expiresIn := accessTokenExpirySeconds * time.Second
	jwtString, err := u.jwtSigner.Sign(userID, sessionID, clientID, sess.TokenVersion(), accessJTI, expiresIn)
	if err != nil {
		return nil, fmt.Errorf("sign jwt: %w", err)
	}

	// ID Token 発行（openid scope 想定、nonce は authcode から取得）
	var idToken string
	if u.issuer != "" {
		idToken, err = u.jwtSigner.SignIDToken(u.issuer, userID.String(), clientID.String(), nonce, authTime, idTokenExpirySeconds*time.Second)
		if err != nil {
			return nil, fmt.Errorf("sign id token: %w", err)
		}
	}

	expiresAt := time.Now().Add(expiresIn)
	accessTokenID, err := u.tokenRepo.SaveAccessToken(ctx, userID, clientID, sessionID, accessJTI, scopes, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("save access token: %w", err)
	}

	refreshToken, err := gen()
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
		ExpiresIn:    accessTokenExpirySeconds,
		RefreshToken: refreshToken,
		Scope:        scopes,
		IDToken:      idToken,
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
