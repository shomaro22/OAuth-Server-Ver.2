package port

import "context"

// TransactionRunner はトランザクション実行のインターフェース。
// コールバック内の DB 操作は同一トランザクションで実行される。
// 実装は ctx に tx を格納し、Repository が ctx から tx を取得して使用する。
type TransactionRunner interface {
	Transaction(ctx context.Context, fn func(ctx context.Context) error) error
}
