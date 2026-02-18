package port

import (
	"context"

	"github.com/google/uuid"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/session"
)

// SessionRepository はセッションの永続化インターフェース。
type SessionRepository interface {
	Save(ctx context.Context, s *session.Session) error

	// FindBySessionTokenHash はデバイス識別（cookie等）のトークンハッシュでセッションを取得する。
	FindBySessionTokenHash(ctx context.Context, tokenHash string) (*session.Session, error)

	// IncrementTokenVersion は token_version をインクリメントする（即時失効用）。
	IncrementTokenVersion(ctx context.Context, sid uuid.UUID) error

	// Revoke はセッションを失効させる。
	Revoke(ctx context.Context, sid uuid.UUID) error
}
