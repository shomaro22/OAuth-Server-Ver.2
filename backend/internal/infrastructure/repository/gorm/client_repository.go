package gorm

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/infrastructure/db/models"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/port"
)

var _ port.ClientRepository = (*ClientRepository)(nil)

// ClientRepository は GORM による ClientRepository の実装。
type ClientRepository struct {
	db *gorm.DB
}

// NewClientRepository は ClientRepository を生成する。
func NewClientRepository(db *gorm.DB) *ClientRepository {
	return &ClientRepository{db: db}
}

// Exists はクライアントが存在するかどうかを返す。
func (r *ClientRepository) Exists(ctx context.Context, clientID uuid.UUID) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.ClientModel{}).Where("id = ?", clientID).Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// ValidateRedirectURI は redirect_uri がクライアントに登録されているか検証する。
func (r *ClientRepository) ValidateRedirectURI(ctx context.Context, clientID uuid.UUID, redirectURI string) (bool, error) {
	var m models.ClientModel
	err := r.db.WithContext(ctx).Where("id = ?", clientID).First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}
	uris := strings.FieldsFunc(m.RedirectURIs, func(r rune) bool {
		return r == ',' || r == '\n' || r == ' '
	})
	for _, uri := range uris {
		if strings.TrimSpace(uri) == redirectURI {
			return true, nil
		}
	}
	return false, nil
}

// dummyBcryptHash は client が存在しない場合のタイミング攻撃対策用。
// 存在しない client でも bcrypt を1回回し、応答時間差で client の存在を推測されないようにする。
// bcrypt.GenerateFromPassword([]byte("dummy-timing-attack"), bcrypt.DefaultCost) で生成した固定ハッシュ
const dummyBcryptHash = "$2a$10$cZPGFEuZkd1TEWgZ1GFAmuqNTygVRNE.huBdcioIXAD2o5oTkQp9S"

// ValidateClientCredentials は client_id + client_secret でクライアント認証する。
// DB には client_secret_hash（bcrypt）を保存し、bcrypt.CompareHashAndPassword で照合する。
func (r *ClientRepository) ValidateClientCredentials(ctx context.Context, clientID uuid.UUID, clientSecret string) (bool, error) {
	if clientSecret == "" {
		return false, nil
	}
	var m models.ClientModel
	err := r.db.WithContext(ctx).Where("id = ?", clientID).First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			_ = bcrypt.CompareHashAndPassword([]byte(dummyBcryptHash), []byte(clientSecret))
			return false, nil
		}
		return false, err
	}
	if m.ClientSecretHash == "" {
		return false, nil
	}
	err = bcrypt.CompareHashAndPassword([]byte(m.ClientSecretHash), []byte(clientSecret))
	return err == nil, nil
}

// GetAllowedScopes はクライアントが許可する scope の一覧を返す。
func (r *ClientRepository) GetAllowedScopes(ctx context.Context, clientID uuid.UUID) ([]string, error) {
	var m models.ClientModel
	err := r.db.WithContext(ctx).Where("id = ?", clientID).First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if m.AllowedScopes == "" {
		return []string{"openid", "profile", "email"}, nil
	}
	scopes := strings.FieldsFunc(m.AllowedScopes, func(r rune) bool {
		return r == ',' || r == '\n' || r == ' ' || r == '\t'
	})
	result := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if t := strings.TrimSpace(s); t != "" {
			result = append(result, t)
		}
	}
	if len(result) == 0 {
		return []string{"openid", "profile", "email"}, nil
	}
	return result, nil
}
