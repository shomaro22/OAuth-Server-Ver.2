package models

import (
	"github.com/google/uuid"
)

// ClientModelはclientsテーブルのGORMモデル。
// ClientSecretHashはbcryptハッシュ（平文保存禁止）。
type ClientModel struct {
	ID               uuid.UUID `gorm:"type:uuid;primaryKey"`
	ClientSecretHash string    `gorm:"column:client_secret_hash;type:varchar(255)"`
	RedirectURIs     string    `gorm:"column:redirect_uris;type:text"`
	AllowedScopes    string    `gorm:"column:allowed_scopes;type:varchar(512)"`
}

// TableNameはテーブル名を返す。
func (ClientModel) TableName() string {
	return "clients"
}
