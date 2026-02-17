package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TokenRepository はアクセストークン・リフレッシュトークンの永続化インターフェース。
type TokenRepository interface {
	SaveAccessToken(ctx context.Context, userID, clientID uuid.UUID, tokenJTI, scopes string, expiresAt time.Time) (uuid.UUID, error)
	SaveRefreshToken(ctx context.Context, accessTokenID uuid.UUID, tokenHash string, expiresAt time.Time) (uuid.UUID, error)
	FindAccessTokenByJTI(ctx context.Context, tokenJTI string) (*AccessTokenRow, error)
	FindRefreshTokenByHash(ctx context.Context, tokenHash string) (*RefreshTokenRow, error)
	RevokeAccessToken(ctx context.Context, id uuid.UUID) error
	RevokeRefreshToken(ctx context.Context, id uuid.UUID) error
}

// AccessTokenRow は access_tokens テーブルの行。
type AccessTokenRow struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	ClientID  uuid.UUID
	TokenJTI  string
	Scopes    string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Revoked   bool
}

// RefreshTokenRow は refresh_tokens テーブルの行。
type RefreshTokenRow struct {
	ID            uuid.UUID
	AccessTokenID uuid.UUID
	TokenHash     string
	ExpiresAt     time.Time
	Revoked       bool
	Rotated       bool
}

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
func (r *PostgresTokenRepository) FindAccessTokenByJTI(ctx context.Context, tokenJTI string) (*AccessTokenRow, error) {
	query := `SELECT id, user_id, client_id, token_jti, scopes, issued_at, expires_at, revoked
		FROM access_tokens WHERE token_jti = $1`
	var row AccessTokenRow
	err := r.pool.QueryRow(ctx, query, tokenJTI).Scan(
		&row.ID,
		&row.UserID,
		&row.ClientID,
		&row.TokenJTI,
		&row.Scopes,
		&row.IssuedAt,
		&row.ExpiresAt,
		&row.Revoked,
	)
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// FindRefreshTokenByHash はハッシュでリフレッシュトークンを取得する。
func (r *PostgresTokenRepository) FindRefreshTokenByHash(ctx context.Context, tokenHash string) (*RefreshTokenRow, error) {
	query := `SELECT id, access_token_id, token_hash, expires_at, revoked, rotated
		FROM refresh_tokens WHERE token_hash = $1`
	var row RefreshTokenRow
	err := r.pool.QueryRow(ctx, query, tokenHash).Scan(
		&row.ID,
		&row.AccessTokenID,
		&row.TokenHash,
		&row.ExpiresAt,
		&row.Revoked,
		&row.Rotated,
	)
	if err != nil {
		return nil, err
	}
	return &row, nil
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
