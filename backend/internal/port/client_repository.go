package port

import (
	"context"

	"github.com/google/uuid"
)

// ClientRepository はOAuthクライアントの取得・検証インターフェース。
type ClientRepository interface {
	ValidateRedirectURI(ctx context.Context, clientID uuid.UUID, redirectURI string) (bool, error)
}
