package introspect

import "context"

// Interactor はトークンイントロスペクトのユースケースインターフェース。
// handler はこの interface に依存し、具象 *UseCase に依存しない。
type Interactor interface {
	Introspect(ctx context.Context, in *IntrospectInput) (*IntrospectOutput, error)
}
