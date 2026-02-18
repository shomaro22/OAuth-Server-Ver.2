package userinfo

import "context"

// Interactor はユーザー情報取得のユースケースインターフェース。
// handler はこの interface に依存し、具象 *UseCase に依存しない。
type Interactor interface {
	Get(ctx context.Context, in *GetInput) (*GetOutput, error)
}
