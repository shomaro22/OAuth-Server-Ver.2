package logout

import "context"

// Interactor はログアウトのユースケースインターフェース。
// handler はこの interface に依存し、具象 *UseCase に依存しない。
type Interactor interface {
	Logout(ctx context.Context, in *LogoutInput) error
}
