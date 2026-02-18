package gorm

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/session"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/infrastructure/db"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/infrastructure/db/models"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/port"
)

var _ port.SessionRepository = (*SessionRepository)(nil)

// SessionRepository は GORM による SessionRepository の実装。
type SessionRepository struct {
	db *gorm.DB
}

// NewSessionRepository は SessionRepository を生成する。
func NewSessionRepository(db *gorm.DB) *SessionRepository {
	return &SessionRepository{db: db}
}

// Save はセッションを保存する。
func (r *SessionRepository) Save(ctx context.Context, s *session.Session) error {
	m := &models.SessionModel{
		ID:               s.ID(),
		UserID:           s.UserID(),
		SessionTokenHash: s.SessionTokenHash(),
		IPAddress:        s.IPAddress(),
		UserAgent:        s.UserAgent(),
		TokenVersion:     s.TokenVersion(),
		ExpiresAt:        s.ExpiresAt(),
		CreatedAt:        s.CreatedAt(),
		Revoked:          s.IsRevoked(),
	}
	return r.exec(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"session_token_hash", "ip_address", "user_agent", "token_version", "expires_at", "revoked"}),
	}).Create(m).Error
}

func (r *SessionRepository) exec(ctx context.Context) *gorm.DB {
	if tx, ok := db.TxFromContext(ctx); ok {
		return tx.WithContext(ctx)
	}
	return r.db.WithContext(ctx)
}

// FindByID はセッションIDでセッションを取得する。
func (r *SessionRepository) FindByID(ctx context.Context, sid uuid.UUID) (*session.Session, error) {
	var m models.SessionModel
	err := r.exec(ctx).Where("id = ?", sid).First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return toSession(&m), nil
}

// FindBySessionTokenHash はトークンハッシュでセッションを取得する。
func (r *SessionRepository) FindBySessionTokenHash(ctx context.Context, tokenHash string) (*session.Session, error) {
	var m models.SessionModel
	err := r.exec(ctx).Where("session_token_hash = ? AND revoked = ?", tokenHash, false).First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return toSession(&m), nil
}

// IncrementTokenVersion は token_version をインクリメントする。
func (r *SessionRepository) IncrementTokenVersion(ctx context.Context, sid uuid.UUID) error {
	return r.exec(ctx).Model(&models.SessionModel{}).Where("id = ?", sid).Update("token_version", gorm.Expr("token_version + 1")).Error
}

// Revoke はセッションを失効させる。
func (r *SessionRepository) Revoke(ctx context.Context, sid uuid.UUID) error {
	return r.exec(ctx).Model(&models.SessionModel{}).Where("id = ?", sid).Update("revoked", true).Error
}

func toSession(m *models.SessionModel) *session.Session {
	return session.Reconstruct(m.ID, m.UserID, m.SessionTokenHash, m.IPAddress, m.UserAgent, m.TokenVersion, m.ExpiresAt, m.CreatedAt, m.Revoked)
}
