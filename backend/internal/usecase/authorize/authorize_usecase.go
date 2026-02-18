package authorize

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/authcode"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/session"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/port"
)

// 認可コードの有効期限（10分）
const codeExpiryMinutes = 10

// セッションの有効期限（24時間）
const sessionExpiryHours = 24

var (
	ErrInvalidRedirectURI   = errors.New("invalid redirect_uri")
	ErrClientNotFound       = errors.New("client not found")
	ErrUnsupportedPKCE      = errors.New("PKCE: only S256 is supported")
	ErrInvalidResponseType  = errors.New("response_type must be code")
	ErrCodeChallengeRequired = errors.New("code_challenge is required")
	ErrStateRequired        = errors.New("state is required")
	ErrInvalidScope         = errors.New("scope is invalid or not allowed for client")
)

// UseCase は認可コード発行のユースケース。
// Interactor を実装する。
var _ Interactor = (*UseCase)(nil)

type UseCase struct {
	authCodeRepo port.AuthCodeRepository
	sessionRepo  port.SessionRepository
	clientRepo   port.ClientRepository
}

// NewUseCase は UseCase を生成する。
func NewUseCase(
	authCodeRepo port.AuthCodeRepository,
	sessionRepo port.SessionRepository,
	clientRepo port.ClientRepository,
) *UseCase {
	return &UseCase{
		authCodeRepo: authCodeRepo,
		sessionRepo:  sessionRepo,
		clientRepo:   clientRepo,
	}
}

// ValidateAuthorizeRequest は認可リクエストのパラメータを検証する。
func (u *UseCase) ValidateAuthorizeRequest(ctx context.Context, in *ValidateAuthorizeInput) error {
	if in.RedirectURI == "" || in.ClientID == uuid.Nil {
		return ErrInvalidRedirectURI
	}
	valid, err := u.clientRepo.ValidateRedirectURI(ctx, in.ClientID, in.RedirectURI)
	if err != nil {
		return fmt.Errorf("validate redirect_uri: %w", err)
	}
	if !valid {
		return ErrInvalidRedirectURI
	}
	if in.ResponseType != "code" {
		return ErrInvalidResponseType
	}
	if in.CodeChallenge == "" {
		return ErrCodeChallengeRequired
	}
	if in.CodeChallengeMethod != authcode.CodeChallengeMethodS256 {
		return ErrUnsupportedPKCE
	}
	if in.State == "" {
		return ErrStateRequired
	}
	scope := in.Scope
	if scope == "" {
		scope = "openid"
	}
	return u.validateScope(ctx, in.ClientID, scope)
}

// IssueCode は認可コードを発行し、セッションを生成する。
func (u *UseCase) IssueCode(ctx context.Context, in *IssueCodeInput) (*IssueCodeOutput, error) {
	// 1. redirect_uri の検証（client 登録済み URI と完全一致）
	valid, err := u.clientRepo.ValidateRedirectURI(ctx, in.ClientID, in.RedirectURI)
	if err != nil {
		return nil, fmt.Errorf("validate redirect_uri: %w", err)
	}
	if !valid {
		return nil, ErrInvalidRedirectURI
	}

	// 2. response_type=code 固定
	if in.ResponseType != "code" {
		return nil, ErrInvalidResponseType
	}

	// 3. code_challenge 必須、code_challenge_method=S256 固定（plain 禁止）
	if in.CodeChallenge == "" {
		return nil, ErrCodeChallengeRequired
	}
	if in.CodeChallengeMethod != authcode.CodeChallengeMethodS256 {
		return nil, ErrUnsupportedPKCE
	}

	// 4. state 必須
	if in.State == "" {
		return nil, ErrStateRequired
	}

	// 5. scope 検証（client 許可 scope 内か）
	if err := u.validateScope(ctx, in.ClientID, in.Scopes); err != nil {
		return nil, err
	}

	// 6. 認可コードの生成（平文を生成し、ハッシュをDBに保存）
	plainCode, err := generateSecureCode()
	if err != nil {
		return nil, fmt.Errorf("generate code: %w", err)
	}
	codeHash := hashCode(plainCode)

	// 4. セッションの取得または作成（FindBySessionTokenHash でデバイス単位の既存セッションを再利用）
	tokenVersion := int64(1)
	expiresAt := time.Now().Add(sessionExpiryHours * time.Hour)
	var sess *session.Session

	existing, err := u.sessionRepo.FindBySessionTokenHash(ctx, in.SessionTokenHash)
	if err != nil {
		return nil, fmt.Errorf("find session: %w", err)
	}
	if existing != nil {
		if existing.IsValid(time.Now()) {
			// 既存セッションを再利用
			sess = existing
		} else {
			// 無効なセッションは Revoke してから新規作成
			if err := u.sessionRepo.Revoke(ctx, existing.ID()); err != nil {
				return nil, fmt.Errorf("revoke invalid session: %w", err)
			}
			sess = session.New(
				in.UserID,
				in.SessionTokenHash,
				in.IPAddress,
				in.UserAgent,
				tokenVersion,
				expiresAt,
			)
			if err := u.sessionRepo.Save(ctx, sess); err != nil {
				return nil, fmt.Errorf("save session: %w", err)
			}
		}
	} else {
		// 見つからない＝新規作成
		sess = session.New(
			in.UserID,
			in.SessionTokenHash,
			in.IPAddress,
			in.UserAgent,
			tokenVersion,
			expiresAt,
		)
		if err := u.sessionRepo.Save(ctx, sess); err != nil {
			return nil, fmt.Errorf("save session: %w", err)
		}
	}

	// 5. 認可コードの作成と保存（session_id を紐付け）
	codeExpiresAt := time.Now().Add(codeExpiryMinutes * time.Minute)
	authCodeEntity := authcode.New(
		in.UserID,
		in.ClientID,
		sess.ID(),
		codeHash,
		in.CodeChallenge,
		in.CodeChallengeMethod,
		in.RedirectURI,
		in.Scopes,
		in.Nonce,
		codeExpiresAt,
	)

	if err := u.authCodeRepo.Save(ctx, authCodeEntity); err != nil {
		return nil, fmt.Errorf("save authorization code: %w", err)
	}

	return &IssueCodeOutput{
		Code:        plainCode,
		RedirectURI: in.RedirectURI,
		State:       in.State,
	}, nil
}

// generateSecureCode は暗号学的に安全なランダムコードを生成する。
func generateSecureCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b), nil
}

// hashCode はコードをSHA-256でハッシュ化する。
func hashCode(code string) string {
	h := sha256.Sum256([]byte(code))
	return hex.EncodeToString(h[:])
}

// validateScope はリクエスト scope が client の許可 scope 内か検証する。
func (u *UseCase) validateScope(ctx context.Context, clientID uuid.UUID, requestedScope string) error {
	allowed, err := u.clientRepo.GetAllowedScopes(ctx, clientID)
	if err != nil {
		return fmt.Errorf("get allowed scopes: %w", err)
	}
	if len(allowed) == 0 {
		allowed = []string{"openid", "profile", "email"}
	}
	allowedSet := make(map[string]bool)
	for _, s := range allowed {
		allowedSet[s] = true
	}
	// リクエスト scope はスペース区切り
	requested := strings.Fields(requestedScope)
	for _, s := range requested {
		if !allowedSet[s] {
			return ErrInvalidScope
		}
	}
	return nil
}
