package logout

import (
	"context"
	"errors"

	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/port"
)

var (
	ErrSessionNotFound = errors.New("session not found")
)

// UseCase はログアウトのユースケース。
type UseCase struct {
	sessionRepo port.SessionRepository
}

// NewUseCase は UseCase を生成する。
func NewUseCase(sessionRepo port.SessionRepository) *UseCase {
	return &UseCase{
		sessionRepo: sessionRepo,
	}
}

// LogoutInput はログアウトの入力（cookie の session token をハッシュ化した値）。
type LogoutInput struct {
	SessionTokenHash string
}

// Logout はセッションを失効させる（この端末だけログアウト）。
func (u *UseCase) Logout(ctx context.Context, in *LogoutInput) error {
	sess, err := u.sessionRepo.FindBySessionTokenHash(ctx, in.SessionTokenHash)
	if err != nil || sess == nil {
		return ErrSessionNotFound
	}

	return u.sessionRepo.Revoke(ctx, sess.ID())
}
