package postgres

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/port"
)

// Ensure PostgresClientRepository implements port.ClientRepository.
var _ port.ClientRepository = (*PostgresClientRepository)(nil)

// PostgresClientRepository は PostgreSQL による ClientRepository の実装。
type PostgresClientRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresClientRepository は PostgresClientRepository を生成する。
func NewPostgresClientRepository(pool *pgxpool.Pool) *PostgresClientRepository {
	return &PostgresClientRepository{pool: pool}
}

// ValidateRedirectURI は redirect_uri がクライアントに登録されているか検証する。
func (r *PostgresClientRepository) ValidateRedirectURI(ctx context.Context, clientID uuid.UUID, redirectURI string) (bool, error) {
	query := `SELECT redirect_uris FROM clients WHERE id = $1`
	var redirectURIs string
	err := r.pool.QueryRow(ctx, query, clientID).Scan(&redirectURIs)
	if err != nil {
		return false, err
	}
	// redirect_uris はカンマまたは改行区切り
	uris := strings.FieldsFunc(redirectURIs, func(r rune) bool {
		return r == ',' || r == '\n' || r == ' '
	})
	for _, uri := range uris {
		if strings.TrimSpace(uri) == redirectURI {
			return true, nil
		}
	}
	return false, nil
}
