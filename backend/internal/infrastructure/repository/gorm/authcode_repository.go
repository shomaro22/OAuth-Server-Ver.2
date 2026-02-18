package gorm

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/authcode"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/infrastructure/db"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/infrastructure/db/models"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/port"
)

var _ port.AuthCodeRepository = (*AuthCodeRepository)(nil)

// AuthCodeRepository は GORM による AuthCodeRepository の実装。
type AuthCodeRepository struct {
	db *gorm.DB
}

// NewAuthCodeRepository は AuthCodeRepository を生成する。
func NewAuthCodeRepository(db *gorm.DB) *AuthCodeRepository {
	return &AuthCodeRepository{db: db}
}

// Save は認可コードを保存する。
func (r *AuthCodeRepository) Save(ctx context.Context, code *authcode.AuthorizationCode) error {
	m := &models.AuthCodeModel{
		ID:                  code.ID(),
		UserID:              code.UserID(),
		ClientID:            code.ClientID(),
		SessionID:           code.SessionID(),
		CodeHash:            code.CodeHash(),
		CodeChallenge:       code.CodeChallenge(),
		CodeChallengeMethod: code.CodeChallengeMethod(),
		RedirectURI:         code.RedirectURI(),
		Scopes:              code.Scopes(),
		Nonce:               code.Nonce(),
		ExpiresAt:           code.ExpiresAt(),
		Consumed:            code.IsConsumed(),
		CreatedAt:           code.CreatedAt(),
	}
	return r.db.WithContext(ctx).Create(m).Error
}

// FindByCodeHash はコードハッシュで認可コードを取得する。
func (r *AuthCodeRepository) FindByCodeHash(ctx context.Context, codeHash string) (*authcode.AuthorizationCode, error) {
	return r.findByCodeHash(ctx, codeHash, false)
}

// FindByCodeHashForUpdate はコードハッシュで認可コードをロックして取得する（SELECT FOR UPDATE）。
func (r *AuthCodeRepository) FindByCodeHashForUpdate(ctx context.Context, codeHash string) (*authcode.AuthorizationCode, error) {
	return r.findByCodeHash(ctx, codeHash, true)
}

func (r *AuthCodeRepository) findByCodeHash(ctx context.Context, codeHash string, forUpdate bool) (*authcode.AuthorizationCode, error) {
	exec := r.db.WithContext(ctx)
	if tx, ok := db.TxFromContext(ctx); ok {
		exec = tx.WithContext(ctx)
	}
	query := exec.Where("code_hash = ?", codeHash)
	if forUpdate {
		query = query.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var m models.AuthCodeModel
	err := query.First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return toAuthCode(&m), nil
}

// MarkConsumed は認可コードを消費済みにする。戻り値の rowsAffected が 1 でない場合は二重交換の可能性あり。
func (r *AuthCodeRepository) MarkConsumed(ctx context.Context, id uuid.UUID) (int64, error) {
	exec := r.db.WithContext(ctx)
	if tx, ok := db.TxFromContext(ctx); ok {
		exec = tx.WithContext(ctx)
	}
	result := exec.Model(&models.AuthCodeModel{}).Where("id = ? AND consumed = ?", id, false).Update("consumed", true)
	return result.RowsAffected, result.Error
}

// Delete は認可コードを削除する。
func (r *AuthCodeRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Where("id = ?", id).Delete(&models.AuthCodeModel{}).Error
}

func toAuthCode(m *models.AuthCodeModel) *authcode.AuthorizationCode {
	return authcode.Reconstruct(
		m.ID, m.UserID, m.ClientID, m.SessionID,
		m.CodeHash, m.CodeChallenge, m.CodeChallengeMethod,
		m.RedirectURI, m.Scopes, m.Nonce, m.ExpiresAt, m.Consumed, m.CreatedAt,
	)
}
