package authorize

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/authcode"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/session"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/port"
)

// 認可コードの有効期限（10分）
const codeExpiryMinutes = 10

// セッションの有効期限（24時間）
const sessionExpiryHours = 24

var (
	ErrInvalidRedirectURI = errors.New("invalid redirect_uri")
	ErrClientNotFound     = errors.New("client not found")
)

// UseCase は認可コード発行のユースケース。
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

// IssueCode は認可コードを発行し、セッションを生成する。
func (u *UseCase) IssueCode(ctx context.Context, in *IssueCodeInput) (*IssueCodeOutput, error) {
	// 1. redirect_uri の検証
	valid, err := u.clientRepo.ValidateRedirectURI(ctx, in.ClientID, in.RedirectURI)
	if err != nil {
		return nil, fmt.Errorf("validate redirect_uri: %w", err)
	}
	if !valid {
		return nil, ErrInvalidRedirectURI
	}

	// 2. 認可コードの生成（平文を生成し、ハッシュをDBに保存）
	plainCode, err := generateSecureCode()
	if err != nil {
		return nil, fmt.Errorf("generate code: %w", err)
	}
	codeHash := hashCode(plainCode)

	// 3. セッションの取得または作成（FindBySessionTokenHash でデバイス単位の既存セッションを再利用）
	tokenVersion := int64(1)
	expiresAt := time.Now().Add(sessionExpiryHours * time.Hour)

	existing, err := u.sessionRepo.FindBySessionTokenHash(ctx, in.SessionTokenHash)
	if err == nil && existing != nil && existing.IsValid(time.Now()) {
		// 既存セッションを再利用（新規作成しない）
		_ = existing
	} else {
		sess := session.New(
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

	// 4. 認可コードの作成と保存
	codeExpiresAt := time.Now().Add(codeExpiryMinutes * time.Minute)
	authCodeEntity := authcode.New(
		in.UserID,
		in.ClientID,
		codeHash,
		in.CodeChallenge,
		in.CodeChallengeMethod,
		in.RedirectURI,
		in.Scopes,
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
