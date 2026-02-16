package session

import (
	"time"

	"github.com/google/uuid"
)

// Session はセッションのドメインエンティティ。
// token_version による即時失効をサポートする。
type Session struct {
	id               uuid.UUID
	userID           uuid.UUID
	sessionTokenHash string
	ipAddress        string
	userAgent        string
	tokenVersion     int64
	expiresAt        time.Time
	createdAt        time.Time
	revoked          bool
}

// New は新しい Session を作成する。
func New(
	userID uuid.UUID,
	sessionTokenHash string,
	ipAddress string,
	userAgent string,
	tokenVersion int64,
	expiresAt time.Time,
) *Session {
	now := time.Now()
	return &Session{
		id:               uuid.New(),
		userID:           userID,
		sessionTokenHash: sessionTokenHash,
		ipAddress:        ipAddress,
		userAgent:        userAgent,
		tokenVersion:     tokenVersion,
		expiresAt:        expiresAt,
		createdAt:       now,
		revoked:          false,
	}
}

// ID はセッションIDを返す。
func (s *Session) ID() uuid.UUID {
	return s.id
}

// UserID はユーザーIDを返す。
func (s *Session) UserID() uuid.UUID {
	return s.userID
}

// TokenVersion はトークンバージョンを返す。
func (s *Session) TokenVersion() int64 {
	return s.tokenVersion
}

// ExpiresAt は有効期限を返す。
func (s *Session) ExpiresAt() time.Time {
	return s.expiresAt
}

// IsExpired は有効期限切れかどうかを判定する。
func (s *Session) IsExpired(now time.Time) bool {
	return now.After(s.expiresAt)
}

// IsRevoked は失効済みかどうかを判定する。
func (s *Session) IsRevoked() bool {
	return s.revoked
}

// IsValid はセッションが有効かどうかを判定する。
// 有効期限切れまたは失効済みの場合は false。
func (s *Session) IsValid(now time.Time) bool {
	return !s.IsExpired(now) && !s.IsRevoked()
}

// IncrementVersion は token_version をインクリメントする。
// 即時失効（ログアウト等）時に呼び出す。
func (s *Session) IncrementVersion() {
	s.tokenVersion++
}

// Revoke はセッションを失効させる。
func (s *Session) Revoke() {
	s.revoked = true
}

// UpdateExpiry は有効期限を更新する。
func (s *Session) UpdateExpiry(expiresAt time.Time) {
	s.expiresAt = expiresAt
}

// Reconstruct は永続化層から復元するためのファクトリ。
// Repository が DB から読み込んだ値を渡す。
func Reconstruct(
	id uuid.UUID,
	userID uuid.UUID,
	sessionTokenHash string,
	ipAddress string,
	userAgent string,
	tokenVersion int64,
	expiresAt time.Time,
	createdAt time.Time,
	revoked bool,
) *Session {
	return &Session{
		id:               id,
		userID:           userID,
		sessionTokenHash: sessionTokenHash,
		ipAddress:        ipAddress,
		userAgent:        userAgent,
		tokenVersion:     tokenVersion,
		expiresAt:        expiresAt,
		createdAt:       createdAt,
		revoked:          revoked,
	}
}
