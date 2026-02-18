package models

import (
	"time"

	"github.com/google/uuid"
)

// AuthCodeModelはauthorization_codesテーブルのGORMモデル。
type AuthCodeModel struct {
	ID                  uuid.UUID `gorm:"type:uuid;primaryKey"`
	UserID              uuid.UUID `gorm:"type:uuid;index;not null"`
	ClientID            uuid.UUID `gorm:"type:uuid;index;not null"`
	SessionID           uuid.UUID `gorm:"type:uuid;index;not null"`
	CodeHash            string    `gorm:"type:varchar(255);uniqueIndex;not null"`
	CodeChallenge       string    `gorm:"type:varchar(255)"`
	CodeChallengeMethod string    `gorm:"type:varchar(10)"`
	RedirectURI         string    `gorm:"type:varchar(512);not null"`
	Scopes              string    `gorm:"type:varchar(512)"`
	Nonce               string    `gorm:"type:varchar(255)"`
	ExpiresAt           time.Time `gorm:"not null"`
	Consumed            bool      `gorm:"not null;default:false"`
	CreatedAt           time.Time `gorm:"not null"`
}

// TableNameはテーブル名を返す。
func (AuthCodeModel) TableName() string {
	return "authorization_codes"
}
