package port

import (
	"context"

	"github.com/google/uuid"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/authcode"
)

// AuthCodeRepository は認可コードの永続化インターフェース。
type AuthCodeRepository interface {
	Save(ctx context.Context, code *authcode.AuthorizationCode) error
	FindByCodeHash(ctx context.Context, codeHash string) (*authcode.AuthorizationCode, error)
	MarkConsumed(ctx context.Context, id uuid.UUID) error
	Delete(ctx context.Context, id uuid.UUID) error
}
