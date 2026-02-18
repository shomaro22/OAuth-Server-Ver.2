package db

import (
	"context"

	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/port"
	"gorm.io/gorm"
)

type txKey struct{}

// WithTx は context にトランザクションを格納する。
func WithTx(ctx context.Context, tx *gorm.DB) context.Context {
	return context.WithValue(ctx, txKey{}, tx)
}

// TxFromContext は context からトランザクションを取得する。
func TxFromContext(ctx context.Context) (*gorm.DB, bool) {
	tx, ok := ctx.Value(txKey{}).(*gorm.DB)
	return tx, ok
}

// GormTransactionRunner は GORM による TransactionRunner の実装。
type GormTransactionRunner struct {
	db *gorm.DB
}

// NewTransactionRunner は TransactionRunner を生成する。
func NewTransactionRunner(db *gorm.DB) port.TransactionRunner {
	return &GormTransactionRunner{db: db}
}

// Transaction はトランザクション内で fn を実行する。
func (r *GormTransactionRunner) Transaction(ctx context.Context, fn func(ctx context.Context) error) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		txCtx := WithTx(ctx, tx)
		return fn(txCtx)
	})
}
