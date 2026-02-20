package gorm

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/user"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/infrastructure/db/models"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/port"
)

var _ port.UserRepository = (*UserRepository)(nil)

// UserRepository は GORM による UserRepository の実装。
type UserRepository struct {
	db *gorm.DB
}

// NewUserRepository は UserRepository を生成する。
func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

// FindByID はIDでユーザーを取得する。
func (r *UserRepository) FindByID(ctx context.Context, id uuid.UUID) (*user.User, error) {
	var m models.UserModel
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return toUser(&m), nil
}

// FindByUsername はユーザー名でユーザーを取得する（ログイン認証用、password_hash も返す）。
func (r *UserRepository) FindByUsername(ctx context.Context, username string) (*user.User, string, error) {
	var m models.UserModel
	err := r.db.WithContext(ctx).Where("username = ?", username).First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, "", nil
		}
		return nil, "", err
	}
	return toUser(&m), m.PasswordHash, nil
}

// Save はユーザーを保存する。
func (r *UserRepository) Save(ctx context.Context, u *user.User) error {
	m := &models.UserModel{
		ID:            u.ID(),
		Email:         u.Email(),
		Username:      u.Username(),
		EmailVerified: u.EmailVerified(),
		Status:        u.Status(),
		CreatedAt:     u.CreatedAt(),
		UpdatedAt:     u.UpdatedAt(),
	}
	return r.db.WithContext(ctx).Save(m).Error
}

func toUser(m *models.UserModel) *user.User {
	return user.NewUser(m.ID, m.Email, m.Username, m.EmailVerified, m.Status, m.CreatedAt, m.UpdatedAt)
}
