package token

import (
	"time"

	"github.com/google/uuid"
)

// RefreshToken はリフレッシュトークンのドメインエンティティ。
type RefreshToken struct {
	id            uuid.UUID
	accessTokenID uuid.UUID
	tokenHash     string
	expiresAt     time.Time
	revoked       bool
	rotated       bool
}

// NewRefreshToken は RefreshToken を生成する（永続化層からの再構築用）。
func NewRefreshToken(id, accessTokenID uuid.UUID, tokenHash string, expiresAt time.Time, revoked, rotated bool) *RefreshToken {
	return &RefreshToken{
		id:            id,
		accessTokenID: accessTokenID,
		tokenHash:     tokenHash,
		expiresAt:     expiresAt,
		revoked:       revoked,
		rotated:       rotated,
	}
}

func (t *RefreshToken) ID() uuid.UUID            { return t.id }
func (t *RefreshToken) AccessTokenID() uuid.UUID  { return t.accessTokenID }
func (t *RefreshToken) TokenHash() string        { return t.tokenHash }
func (t *RefreshToken) ExpiresAt() time.Time      { return t.expiresAt }
func (t *RefreshToken) Revoked() bool             { return t.revoked }
func (t *RefreshToken) Rotated() bool             { return t.rotated }
