package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/session"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/port"
)

// Ensure PostgresSessionRepository implements port.SessionRepository.
var _ port.SessionRepository = (*PostgresSessionRepository)(nil)

// PostgresSessionRepository は PostgreSQL による SessionRepository の実装。
type PostgresSessionRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresSessionRepository は PostgresSessionRepository を生成する。
func NewPostgresSessionRepository(pool *pgxpool.Pool) *PostgresSessionRepository {
	return &PostgresSessionRepository{pool: pool}
}

// Save はセッションを保存する。
func (r *PostgresSessionRepository) Save(ctx context.Context, s *session.Session) error {
	query := `INSERT INTO sessions (id, user_id, session_token_hash, ip_address, user_agent, token_version, expires_at, created_at, revoked)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (id) DO UPDATE SET
			session_token_hash = EXCLUDED.session_token_hash,
			ip_address = EXCLUDED.ip_address,
			user_agent = EXCLUDED.user_agent,
			token_version = EXCLUDED.token_version,
			expires_at = EXCLUDED.expires_at,
			revoked = EXCLUDED.revoked`
	_, err := r.pool.Exec(ctx, query,
		s.ID(),
		s.UserID(),
		s.SessionTokenHash(),
		s.IPAddress(),
		s.UserAgent(),
		s.TokenVersion(),
		s.ExpiresAt(),
		s.CreatedAt(),
		s.IsRevoked(),
	)
	return err
}

// FindBySessionTokenHash はデバイス識別（cookie等）のトークンハッシュでセッションを取得する。
func (r *PostgresSessionRepository) FindBySessionTokenHash(ctx context.Context, tokenHash string) (*session.Session, error) {
	query := `SELECT id, user_id, session_token_hash, ip_address, user_agent, token_version, expires_at, created_at, revoked
		FROM sessions WHERE session_token_hash = $1 AND revoked = false`
	var (
		id               uuid.UUID
		uid              uuid.UUID
		sessionTokenHash string
		ipAddress        string
		userAgent        string
		tokenVersion     int64
		expiresAt        time.Time
		createdAt        time.Time
		revoked          bool
	)
	err := r.pool.QueryRow(ctx, query, tokenHash).Scan(
		&id,
		&uid,
		&sessionTokenHash,
		&ipAddress,
		&userAgent,
		&tokenVersion,
		&expiresAt,
		&createdAt,
		&revoked,
	)
	if err != nil {
		return nil, err
	}
	return session.Reconstruct(id, uid, sessionTokenHash, ipAddress, userAgent, tokenVersion, expiresAt, createdAt, revoked), nil
}

// IncrementTokenVersion は token_version をインクリメントする。
func (r *PostgresSessionRepository) IncrementTokenVersion(ctx context.Context, sid uuid.UUID) error {
	query := `UPDATE sessions SET token_version = token_version + 1 WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, sid)
	return err
}

// Revoke はセッションを失効させる。
func (r *PostgresSessionRepository) Revoke(ctx context.Context, sid uuid.UUID) error {
	query := `UPDATE sessions SET revoked = true WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, sid)
	return err
}
