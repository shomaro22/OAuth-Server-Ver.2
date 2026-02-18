package models

import (
	"time"

	"github.com/google/uuid"
)

// RefreshTokenModelはrefresh_tokensテーブルのGORMモデル。
type RefreshTokenModel struct {
	ID            uuid.UUID `gorm:"type:uuid;primaryKey"`
	AccessTokenID uuid.UUID `gorm:"column:access_token_id;type:uuid;index;not null"`
	TokenHash     string    `gorm:"column:token_hash;type:varchar(255);uniqueIndex;not null"`
	ExpiresAt     time.Time `gorm:"not null"`
	Revoked       bool      `gorm:"not null;default:false"`
	Rotated       bool      `gorm:"not null;default:false"`
}

// TableNameはテーブル名を返す。
func (RefreshTokenModel) TableName() string {
	return "refresh_tokens"
}
