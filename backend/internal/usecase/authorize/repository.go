package authorize

import (
	"context"

	"github.com/google/uuid"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/authcode"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/session"
)

// CodeHasher は認可コードのハッシュ化インターフェース。
type CodeHasher interface {
	Hash(code string) string
}

// AuthCodeRepository は認可コードの永続化インターフェース。
type AuthCodeRepository interface {
	Save(ctx context.Context, code *authcode.AuthorizationCode) error
	FindByCodeHash(ctx context.Context, codeHash string) (*authcode.AuthorizationCode, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

// SessionRepository はセッションの永続化インターフェース。
type SessionRepository interface {
	Save(ctx context.Context, s *session.Session) error
	FindByUserID(ctx context.Context, userID uuid.UUID) (*session.Session, error)
}

// ClientRepository はOAuthクライアントの取得・検証インターフェース。
type ClientRepository interface {
	ValidateRedirectURI(ctx context.Context, clientID uuid.UUID, redirectURI string) (bool, error)
}
