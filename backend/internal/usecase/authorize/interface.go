package authorize

import "context"

// Interactor は認可コード発行のユースケースインターフェース。
// handler はこの interface に依存し、具象 *UseCase に依存しない。
type Interactor interface {
	// ValidateAuthorizeRequest は認可リクエストのパラメータを検証する（code 発行はしない）。
	ValidateAuthorizeRequest(ctx context.Context, in *ValidateAuthorizeInput) error
	IssueCode(ctx context.Context, in *IssueCodeInput) (*IssueCodeOutput, error)
}
