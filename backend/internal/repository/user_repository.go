package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// UserRepository はユーザーの永続化インターフェース。
type UserRepository interface {
	FindByID(ctx context.Context, id uuid.UUID) (*UserRow, error)
	Save(ctx context.Context, user *UserRow) error
}

// UserRow は users テーブルの行。
type UserRow struct {
	ID            uuid.UUID
	Email         string
	Username      string
	EmailVerified bool
	Status        string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// PostgresUserRepository は PostgreSQL による UserRepository の実装。
type PostgresUserRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresUserRepository は PostgresUserRepository を生成する。
func NewPostgresUserRepository(pool *pgxpool.Pool) *PostgresUserRepository {
	return &PostgresUserRepository{pool: pool}
}

// FindByID はIDでユーザーを取得する。
func (r *PostgresUserRepository) FindByID(ctx context.Context, id uuid.UUID) (*UserRow, error) {
	query := `SELECT id, email, username, email_verified, status, created_at, updated_at
		FROM users WHERE id = $1`
	var row UserRow
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&row.ID,
		&row.Email,
		&row.Username,
		&row.EmailVerified,
		&row.Status,
		&row.CreatedAt,
		&row.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// Save はユーザーを保存する。
func (r *PostgresUserRepository) Save(ctx context.Context, user *UserRow) error {
	query := `INSERT INTO users (id, email, username, email_verified, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
		ON CONFLICT (id) DO UPDATE SET
			email = EXCLUDED.email,
			username = EXCLUDED.username,
			email_verified = EXCLUDED.email_verified,
			status = EXCLUDED.status,
			updated_at = NOW()`
	_, err := r.pool.Exec(ctx, query,
		user.ID,
		user.Email,
		user.Username,
		user.EmailVerified,
		user.Status,
	)
	return err
}
