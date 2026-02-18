package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/user"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/port"
)

// Ensure PostgresUserRepository implements port.UserRepository.
var _ port.UserRepository = (*PostgresUserRepository)(nil)

// PostgresUserRepository は PostgreSQL による UserRepository の実装。
type PostgresUserRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresUserRepository は PostgresUserRepository を生成する。
func NewPostgresUserRepository(pool *pgxpool.Pool) *PostgresUserRepository {
	return &PostgresUserRepository{pool: pool}
}

// FindByID はIDでユーザーを取得する。
func (r *PostgresUserRepository) FindByID(ctx context.Context, id uuid.UUID) (*user.User, error) {
	query := `SELECT id, email, username, email_verified, status, created_at, updated_at
		FROM users WHERE id = $1`
	var (
		rowID         uuid.UUID
		email         string
		username      string
		emailVerified bool
		status        string
		createdAt     time.Time
		updatedAt     time.Time
	)
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&rowID,
		&email,
		&username,
		&emailVerified,
		&status,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		return nil, err
	}
	return user.NewUser(rowID, email, username, emailVerified, status, createdAt, updatedAt), nil
}

// Save はユーザーを保存する。
func (r *PostgresUserRepository) Save(ctx context.Context, u *user.User) error {
	query := `INSERT INTO users (id, email, username, email_verified, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
		ON CONFLICT (id) DO UPDATE SET
			email = EXCLUDED.email,
			username = EXCLUDED.username,
			email_verified = EXCLUDED.email_verified,
			status = EXCLUDED.status,
			updated_at = NOW()`
	_, err := r.pool.Exec(ctx, query,
		u.ID(),
		u.Email(),
		u.Username(),
		u.EmailVerified(),
		u.Status(),
	)
	return err
}
