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

	// FindByCodeHashForUpdate は code をロックして取得（SELECT FOR UPDATE 相当）。
	// ctx にトランザクションが含まれる場合、そのトランザクション内でロック取得。
	FindByCodeHashForUpdate(ctx context.Context, codeHash string) (*authcode.AuthorizationCode, error)

	// MarkConsumed は認可コードを消費済みにする。
	// 戻り値の rowsAffected が 1 でない場合は二重交換の可能性あり。
	MarkConsumed(ctx context.Context, id uuid.UUID) (rowsAffected int64, err error)

	Delete(ctx context.Context, id uuid.UUID) error
}
