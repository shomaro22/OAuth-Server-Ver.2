package models

import (
	"time"

	"github.com/google/uuid"
)

// UserModelはusersテーブルのGORMモデル。
type UserModel struct {
	ID            uuid.UUID `gorm:"type:uuid;primaryKey"`
	Email         string    `gorm:"type:varchar(255);not null"`
	Username      string    `gorm:"type:varchar(255)"`
	EmailVerified bool      `gorm:"column:email_verified;not null;default:false"`
	Status        string    `gorm:"type:varchar(50)"`
	CreatedAt     time.Time `gorm:"column:created_at;not null"`
	UpdatedAt     time.Time `gorm:"column:updated_at;not null"`
}

// TableNameはテーブル名を返す。
func (UserModel) TableName() string {
	return "users"
}
