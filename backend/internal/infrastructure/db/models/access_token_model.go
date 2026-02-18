package models

import (
	"time"

	"github.com/google/uuid"
)

// AccessTokenModelはaccess_tokensテーブルのGORMモデル。
type AccessTokenModel struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey"`
	UserID    uuid.UUID `gorm:"type:uuid;index;not null"`
	ClientID  uuid.UUID `gorm:"type:uuid;index;not null"`
	SessionID uuid.UUID `gorm:"type:uuid;index;not null"`
	TokenJTI  string    `gorm:"column:token_jti;type:varchar(255);uniqueIndex;not null"`
	Scopes    string    `gorm:"type:varchar(512)"`
	IssuedAt  time.Time `gorm:"column:issued_at;not null"`
	ExpiresAt time.Time `gorm:"not null"`
	Revoked   bool      `gorm:"not null;default:false"`
}

// TableNameはテーブル名を返す。
func (AccessTokenModel) TableName() string {
	return "access_tokens"
}
