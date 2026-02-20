package port

import (
	"context"

	"github.com/google/uuid"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/user"
)

// UserRepository はユーザーの永続化インターフェース。
type UserRepository interface {
	FindByID(ctx context.Context, id uuid.UUID) (*user.User, error)
	FindByUsername(ctx context.Context, username string) (*user.User, string, error) // User, passwordHash, error
	Save(ctx context.Context, u *user.User) error
}
