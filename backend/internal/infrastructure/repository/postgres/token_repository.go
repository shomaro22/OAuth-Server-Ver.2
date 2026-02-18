package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/token"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/port"
)

// Ensure PostgresTokenRepository implements port.TokenRepository.
var _ port.TokenRepository = (*PostgresTokenRepository)(nil)

// PostgresTokenRepository は PostgreSQL による TokenRepository の実装。
type PostgresTokenRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresTokenRepository は PostgresTokenRepository を生成する。
func NewPostgresTokenRepository(pool *pgxpool.Pool) *PostgresTokenRepository {
	return &PostgresTokenRepository{pool: pool}
}

// SaveAccessToken はアクセストークンを保存する。
func (r *PostgresTokenRepository) SaveAccessToken(ctx context.Context, userID, clientID uuid.UUID, tokenJTI, scopes string, expiresAt time.Time) (uuid.UUID, error) {
	id := uuid.New()
	query := `INSERT INTO access_tokens (id, user_id, client_id, token_jti, scopes, issued_at, expires_at, revoked)
		VALUES ($1, $2, $3, $4, $5, NOW(), $6, false)`
	_, err := r.pool.Exec(ctx, query, id, userID, clientID, tokenJTI, scopes, expiresAt)
	return id, err
}

// SaveRefreshToken はリフレッシュトークンを保存する。
func (r *PostgresTokenRepository) SaveRefreshToken(ctx context.Context, accessTokenID uuid.UUID, tokenHash string, expiresAt time.Time) (uuid.UUID, error) {
	id := uuid.New()
	query := `INSERT INTO refresh_tokens (id, access_token_id, token_hash, expires_at, revoked, rotated)
		VALUES ($1, $2, $3, $4, false, false)`
	_, err := r.pool.Exec(ctx, query, id, accessTokenID, tokenHash, expiresAt)
	return id, err
}

// FindAccessTokenByJTI はJTIでアクセストークンを取得する。
func (r *PostgresTokenRepository) FindAccessTokenByJTI(ctx context.Context, tokenJTI string) (*token.AccessToken, error) {
	query := `SELECT id, user_id, client_id, token_jti, scopes, issued_at, expires_at, revoked
		FROM access_tokens WHERE token_jti = $1`
	var (
		id        uuid.UUID
		userID    uuid.UUID
		clientID  uuid.UUID
		jti       string
		scopes    string
		issuedAt  time.Time
		expiresAt time.Time
		revoked   bool
	)
	err := r.pool.QueryRow(ctx, query, tokenJTI).Scan(
		&id,
		&userID,
		&clientID,
		&jti,
		&scopes,
		&issuedAt,
		&expiresAt,
		&revoked,
	)
	if err != nil {
		return nil, err
	}
	return token.NewAccessToken(id, userID, clientID, jti, scopes, issuedAt, expiresAt, revoked), nil
}

// FindAccessTokenByID はIDでアクセストークンを取得する。
func (r *PostgresTokenRepository) FindAccessTokenByID(ctx context.Context, id uuid.UUID) (*token.AccessToken, error) {
	query := `SELECT id, user_id, client_id, token_jti, scopes, issued_at, expires_at, revoked
		FROM access_tokens WHERE id = $1`
	var (
		rowID     uuid.UUID
		userID    uuid.UUID
		clientID  uuid.UUID
		jti       string
		scopes    string
		issuedAt  time.Time
		expiresAt time.Time
		revoked   bool
	)
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&rowID,
		&userID,
		&clientID,
		&jti,
		&scopes,
		&issuedAt,
		&expiresAt,
		&revoked,
	)
	if err != nil {
		return nil, err
	}
	return token.NewAccessToken(rowID, userID, clientID, jti, scopes, issuedAt, expiresAt, revoked), nil
}

// FindRefreshTokenByHash はハッシュでリフレッシュトークンを取得する。
func (r *PostgresTokenRepository) FindRefreshTokenByHash(ctx context.Context, tokenHash string) (*token.RefreshToken, error) {
	query := `SELECT id, access_token_id, token_hash, expires_at, revoked, rotated
		FROM refresh_tokens WHERE token_hash = $1`
	var (
		id            uuid.UUID
		accessTokenID uuid.UUID
		hash          string
		expiresAt     time.Time
		revoked       bool
		rotated       bool
	)
	err := r.pool.QueryRow(ctx, query, tokenHash).Scan(
		&id,
		&accessTokenID,
		&hash,
		&expiresAt,
		&revoked,
		&rotated,
	)
	if err != nil {
		return nil, err
	}
	return token.NewRefreshToken(id, accessTokenID, hash, expiresAt, revoked, rotated), nil
}

// RevokeAccessToken はアクセストークンを失効させる。
func (r *PostgresTokenRepository) RevokeAccessToken(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE access_tokens SET revoked = true WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, id)
	return err
}

// RevokeRefreshToken はリフレッシュトークンを失効させる。
func (r *PostgresTokenRepository) RevokeRefreshToken(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE refresh_tokens SET revoked = true WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, id)
	return err
}

// MarkRefreshTokenRotated はリフレッシュトークンをローテーション済みにする。
func (r *PostgresTokenRepository) MarkRefreshTokenRotated(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE refresh_tokens SET rotated = true, revoked = true WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, id)
	return err
}
