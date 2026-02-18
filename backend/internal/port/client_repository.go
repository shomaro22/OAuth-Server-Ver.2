package port

import (
	"context"

	"github.com/google/uuid"
)

// ClientRepository はOAuthクライアントの取得・検証インターフェース。
type ClientRepository interface {
	Exists(ctx context.Context, clientID uuid.UUID) (bool, error)
	ValidateRedirectURI(ctx context.Context, clientID uuid.UUID, redirectURI string) (bool, error)

	// ValidateClientCredentials は client_id + client_secret でクライアント認証する。
	// RFC 7662 のイントロスペクト等で使用。
	ValidateClientCredentials(ctx context.Context, clientID uuid.UUID, clientSecret string) (bool, error)

	// GetAllowedScopes はクライアントが許可する scope の一覧を返す。
	// 空の場合は ["openid","profile","email"] をデフォルトとする。
	GetAllowedScopes(ctx context.Context, clientID uuid.UUID) ([]string, error)
}
