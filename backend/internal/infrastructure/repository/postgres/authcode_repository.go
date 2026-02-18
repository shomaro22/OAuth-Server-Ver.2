package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/authcode"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/port"
)

// Ensure PostgresAuthCodeRepository implements port.AuthCodeRepository.
var _ port.AuthCodeRepository = (*PostgresAuthCodeRepository)(nil)

// PostgresAuthCodeRepository は PostgreSQL による AuthCodeRepository の実装。
type PostgresAuthCodeRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresAuthCodeRepository は PostgresAuthCodeRepository を生成する。
func NewPostgresAuthCodeRepository(pool *pgxpool.Pool) *PostgresAuthCodeRepository {
	return &PostgresAuthCodeRepository{pool: pool}
}

// Save は認可コードを保存する。
func (r *PostgresAuthCodeRepository) Save(ctx context.Context, code *authcode.AuthorizationCode) error {
	query := `INSERT INTO authorization_codes (id, user_id, client_id, code_hash, code_challenge, code_challenge_method, redirect_uri, scopes, expires_at, consumed, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`
	_, err := r.pool.Exec(ctx, query,
		code.ID(),
		code.UserID(),
		code.ClientID(),
		code.CodeHash(),
		code.CodeChallenge(),
		code.CodeChallengeMethod(),
		code.RedirectURI(),
		code.Scopes(),
		code.ExpiresAt(),
		code.IsConsumed(),
		code.CreatedAt(),
	)
	return err
}

// FindByCodeHash はコードハッシュで認可コードを取得する。
func (r *PostgresAuthCodeRepository) FindByCodeHash(ctx context.Context, codeHash string) (*authcode.AuthorizationCode, error) {
	query := `SELECT id, user_id, client_id, code_hash, code_challenge, code_challenge_method, redirect_uri, scopes, expires_at, consumed, created_at
		FROM authorization_codes WHERE code_hash = $1`
	var (
		id                  uuid.UUID
		userID              uuid.UUID
		clientID            uuid.UUID
		hash                string
		codeChallenge       string
		codeChallengeMethod string
		redirectURI         string
		scopes              string
		expiresAt           time.Time
		consumed            bool
		createdAt           time.Time
	)
	err := r.pool.QueryRow(ctx, query, codeHash).Scan(
		&id,
		&userID,
		&clientID,
		&hash,
		&codeChallenge,
		&codeChallengeMethod,
		&redirectURI,
		&scopes,
		&expiresAt,
		&consumed,
		&createdAt,
	)
	if err != nil {
		return nil, err
	}
	return authcode.Reconstruct(id, userID, clientID, hash, codeChallenge, codeChallengeMethod, redirectURI, scopes, expiresAt, consumed, createdAt), nil
}

// MarkConsumed は認可コードを消費済みにする。
func (r *PostgresAuthCodeRepository) MarkConsumed(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE authorization_codes SET consumed = true WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, id)
	return err
}

// Delete は認可コードを削除する。
func (r *PostgresAuthCodeRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM authorization_codes WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, id)
	return err
}
