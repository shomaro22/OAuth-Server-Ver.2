package logout

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/port"
)

var (
	ErrSessionNotFound = errors.New("session not found")
)

// UseCase はログアウトのユースケース。
// Interactor を実装する。
var _ Interactor = (*UseCase)(nil)

type UseCase struct {
	sessionRepo port.SessionRepository
}

// NewUseCase は UseCase を生成する。
func NewUseCase(sessionRepo port.SessionRepository) *UseCase {
	return &UseCase{
		sessionRepo: sessionRepo,
	}
}

// LogoutInput はログアウトの入力（cookie の session token 平文）。
type LogoutInput struct {
	SessionToken string
}

// Logout はセッションを失効させる（この端末だけログアウト）。
func (u *UseCase) Logout(ctx context.Context, in *LogoutInput) error {
	tokenHash := hashString(in.SessionToken)
	sess, err := u.sessionRepo.FindBySessionTokenHash(ctx, tokenHash)
	if err != nil || sess == nil {
		return ErrSessionNotFound
	}

	return u.sessionRepo.Revoke(ctx, sess.ID())
}

func hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
