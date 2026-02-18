package token

import "context"

// Interactor はトークン発行・更新のユースケースインターフェース。
// handler はこの interface に依存し、具象 *UseCase に依存しない。
type Interactor interface {
	Exchange(ctx context.Context, in *ExchangeInput) (*TokenOutput, error)
	Refresh(ctx context.Context, in *RefreshInput) (*TokenOutput, error)
}
