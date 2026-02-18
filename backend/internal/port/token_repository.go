package port

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/token"
)

// TokenRepository はアクセストークン・リフレッシュトークンの永続化インターフェース。
type TokenRepository interface {
	SaveAccessToken(ctx context.Context, userID, clientID uuid.UUID, tokenJTI, scopes string, expiresAt time.Time) (uuid.UUID, error)
	SaveRefreshToken(ctx context.Context, accessTokenID uuid.UUID, tokenHash string, expiresAt time.Time) (uuid.UUID, error)
	FindAccessTokenByJTI(ctx context.Context, tokenJTI string) (*token.AccessToken, error)
	FindAccessTokenByID(ctx context.Context, id uuid.UUID) (*token.AccessToken, error)
	FindRefreshTokenByHash(ctx context.Context, tokenHash string) (*token.RefreshToken, error)
	RevokeAccessToken(ctx context.Context, id uuid.UUID) error
	RevokeRefreshToken(ctx context.Context, id uuid.UUID) error
	MarkRefreshTokenRotated(ctx context.Context, id uuid.UUID) error
}
