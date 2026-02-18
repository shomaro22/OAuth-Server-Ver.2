package gorm

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/token"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/infrastructure/db"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/infrastructure/db/models"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/port"
)

var _ port.TokenRepository = (*TokenRepository)(nil)

// TokenRepository は GORM による TokenRepository の実装。
type TokenRepository struct {
	db *gorm.DB
}

// NewTokenRepository は TokenRepository を生成する。
func NewTokenRepository(db *gorm.DB) *TokenRepository {
	return &TokenRepository{db: db}
}

func (r *TokenRepository) exec(ctx context.Context) *gorm.DB {
	if tx, ok := db.TxFromContext(ctx); ok {
		return tx.WithContext(ctx)
	}
	return r.db.WithContext(ctx)
}

// SaveAccessToken はアクセストークンを保存する。
func (r *TokenRepository) SaveAccessToken(ctx context.Context, userID, clientID, sessionID uuid.UUID, tokenJTI, scopes string, expiresAt time.Time) (uuid.UUID, error) {
	id := uuid.New()
	now := time.Now()
	m := &models.AccessTokenModel{
		ID:        id,
		UserID:    userID,
		ClientID:  clientID,
		SessionID: sessionID,
		TokenJTI:  tokenJTI,
		Scopes:    scopes,
		IssuedAt:  now,
		ExpiresAt: expiresAt,
		Revoked:   false,
	}
	if err := r.exec(ctx).Create(m).Error; err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

// SaveRefreshToken はリフレッシュトークンを保存する。
func (r *TokenRepository) SaveRefreshToken(ctx context.Context, accessTokenID uuid.UUID, tokenHash string, expiresAt time.Time) (uuid.UUID, error) {
	id := uuid.New()
	m := &models.RefreshTokenModel{
		ID:            id,
		AccessTokenID: accessTokenID,
		TokenHash:     tokenHash,
		ExpiresAt:     expiresAt,
		Revoked:       false,
		Rotated:       false,
	}
	if err := r.exec(ctx).Create(m).Error; err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

// FindAccessTokenByJTI はJTIでアクセストークンを取得する。
func (r *TokenRepository) FindAccessTokenByJTI(ctx context.Context, tokenJTI string) (*token.AccessToken, error) {
	var m models.AccessTokenModel
	err := r.exec(ctx).Where("token_jti = ?", tokenJTI).First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return toAccessToken(&m), nil
}

// FindAccessTokenByID はIDでアクセストークンを取得する。
func (r *TokenRepository) FindAccessTokenByID(ctx context.Context, id uuid.UUID) (*token.AccessToken, error) {
	var m models.AccessTokenModel
	err := r.exec(ctx).Where("id = ?", id).First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return toAccessToken(&m), nil
}

// FindRefreshTokenByHash はハッシュでリフレッシュトークンを取得する。
func (r *TokenRepository) FindRefreshTokenByHash(ctx context.Context, tokenHash string) (*token.RefreshToken, error) {
	var m models.RefreshTokenModel
	err := r.exec(ctx).Where("token_hash = ?", tokenHash).First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return toRefreshToken(&m), nil
}

// RevokeAccessToken はアクセストークンを失効させる。
func (r *TokenRepository) RevokeAccessToken(ctx context.Context, id uuid.UUID) error {
	return r.exec(ctx).Model(&models.AccessTokenModel{}).Where("id = ?", id).Update("revoked", true).Error
}

// RevokeRefreshToken はリフレッシュトークンを失効させる。
func (r *TokenRepository) RevokeRefreshToken(ctx context.Context, id uuid.UUID) error {
	return r.exec(ctx).Model(&models.RefreshTokenModel{}).Where("id = ?", id).Update("revoked", true).Error
}

// MarkRefreshTokenRotated はリフレッシュトークンをローテーション済みにする。
func (r *TokenRepository) MarkRefreshTokenRotated(ctx context.Context, id uuid.UUID) error {
	return r.exec(ctx).Model(&models.RefreshTokenModel{}).Where("id = ?", id).Updates(map[string]interface{}{
		"rotated": true,
		"revoked": true,
	}).Error
}

func toAccessToken(m *models.AccessTokenModel) *token.AccessToken {
	return token.NewAccessToken(m.ID, m.UserID, m.ClientID, m.SessionID, m.TokenJTI, m.Scopes, m.IssuedAt, m.ExpiresAt, m.Revoked)
}

func toRefreshToken(m *models.RefreshTokenModel) *token.RefreshToken {
	return token.NewRefreshToken(m.ID, m.AccessTokenID, m.TokenHash, m.ExpiresAt, m.Revoked, m.Rotated)
}
