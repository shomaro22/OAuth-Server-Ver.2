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
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/port"
)

// 認可コードの有効期限（10分）
const codeExpiryMinutes = 10

var loginChallengeTTL = 10 * time.Minute

var (
	ErrInvalidRedirectURI    = errors.New("invalid redirect_uri")
	ErrClientNotFound        = errors.New("client not found")
	ErrUnsupportedPKCE       = errors.New("PKCE: only S256 is supported")
	ErrInvalidResponseType   = errors.New("response_type must be code")
	ErrCodeChallengeRequired = errors.New("code_challenge is required")
	ErrStateRequired         = errors.New("state is required")
	ErrInvalidScope          = errors.New("scope is invalid or not allowed for client")
	ErrChallengeNotFound     = errors.New("login challenge not found or expired")
	ErrSessionRequired       = errors.New("session required")
)

// UseCase は認可コード発行のユースケース。
// Interactor を実装する。
var _ Interactor = (*UseCase)(nil)

type UseCase struct {
	authCodeRepo port.AuthCodeRepository
	clientRepo   port.ClientRepository
	authReqRepo  port.AuthorizationRequestRepository
}

// NewUseCase は UseCase を生成する。
// セッションは触らない。sessionRepo は不要。
func NewUseCase(
	authCodeRepo port.AuthCodeRepository,
	clientRepo port.ClientRepository,
	authReqRepo port.AuthorizationRequestRepository,
) *UseCase {
	return &UseCase{
		authCodeRepo: authCodeRepo,
		clientRepo:   clientRepo,
		authReqRepo:  authReqRepo,
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

// StoredAuthParams は CreateLoginChallenge / GetAndConsumeChallenge の入出力。
type StoredAuthParams struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Prompt              string // login, consent, none
	LoginURL            string // React ログイン画面の URL（CreateLoginChallenge 入力のみ）
}

// CreateLoginChallenge は未ログイン時に authorize リクエストを保存し、login_challenge を発行する。
func (u *UseCase) CreateLoginChallenge(ctx context.Context, params *StoredAuthParams) (challenge, redirectURL string, err error) {
	challenge, err = generateSecureCode()
	if err != nil {
		return "", "", fmt.Errorf("generate challenge: %w", err)
	}
	req := &port.StoredAuthorizationRequest{
		ClientID:            params.ClientID,
		RedirectURI:         params.RedirectURI,
		ResponseType:        params.ResponseType,
		Scope:               params.Scope,
		State:               params.State,
		Nonce:               params.Nonce,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: params.CodeChallengeMethod,
		Prompt:              params.Prompt,
	}
	if err := u.authReqRepo.Save(ctx, challenge, req, loginChallengeTTL); err != nil {
		return "", "", fmt.Errorf("save auth request: %w", err)
	}
	return challenge, params.LoginURL + "?login_challenge=" + challenge, nil
}

// GetChallenge は challenge に紐づく認可リクエストを取得する（消費しない）。
func (u *UseCase) GetChallenge(ctx context.Context, challenge string) (*StoredAuthParams, error) {
	req, err := u.authReqRepo.Get(ctx, challenge)
	if err != nil {
		return nil, fmt.Errorf("get auth request: %w", err)
	}
	if req == nil {
		return nil, ErrChallengeNotFound
	}
	return &StoredAuthParams{
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		ResponseType:        req.ResponseType,
		Scope:               req.Scope,
		State:               req.State,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Prompt:              req.Prompt,
	}, nil
}

// ConsumeChallenge は challenge を削除する（deny 時用）。
func (u *UseCase) ConsumeChallenge(ctx context.Context, challenge string) error {
	return u.authReqRepo.Delete(ctx, challenge)
}

// GetAndConsumeChallenge は challenge に紐づく認可リクエストを取得し、challenge を削除する（one-time）。
func (u *UseCase) GetAndConsumeChallenge(ctx context.Context, challenge string) (*StoredAuthParams, error) {
	req, err := u.authReqRepo.Get(ctx, challenge)
	if err != nil {
		return nil, fmt.Errorf("get auth request: %w", err)
	}
	if req == nil {
		return nil, ErrChallengeNotFound
	}
	if err := u.authReqRepo.Delete(ctx, challenge); err != nil {
		return nil, fmt.Errorf("delete challenge: %w", err)
	}
	return &StoredAuthParams{
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		ResponseType:        req.ResponseType,
		Scope:               req.Scope,
		State:               req.State,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Prompt:              req.Prompt,
	}, nil
}

// IssueCode は認可コードを発行する。
// セッションは /sessions/login で作成済み。SessionID を authcode に紐づけるだけ。セッションは触らない。
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

	// 7. 認可コードの作成と保存（session_id を紐付け。セッションは /sessions/login で作成済み）
	codeExpiresAt := time.Now().Add(codeExpiryMinutes * time.Minute)
	authCodeEntity := authcode.New(
		in.UserID,
		in.ClientID,
		in.SessionID,
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
