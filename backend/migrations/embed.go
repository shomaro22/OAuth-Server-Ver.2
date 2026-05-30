package migrations

import "embed"

// Files は起動時マイグレーション用 SQL（scripts/migrate.sh と同じ順序）。
//
//go:embed *.sql
var Files embed.FS
