package models

import (
	"time"

	"github.com/google/uuid"
)

// SessionModelはsessionsテーブルのGORMモデル。
type SessionModel struct {
	ID               uuid.UUID `gorm:"type:uuid;primaryKey"`
	UserID           uuid.UUID `gorm:"type:uuid;index;not null"`
	SessionTokenHash string    `gorm:"type:varchar(255);index;not null"`
	IPAddress        string    `gorm:"type:varchar(45)"`
	UserAgent        string    `gorm:"type:varchar(512)"`
	TokenVersion     int64     `gorm:"not null;default:1"`
	ExpiresAt        time.Time `gorm:"not null"`
	CreatedAt        time.Time `gorm:"not null"`
	Revoked          bool      `gorm:"not null;default:false"`
}

// TableNameはテーブル名を返す。
func (SessionModel) TableName() string {
	return "sessions"
}
