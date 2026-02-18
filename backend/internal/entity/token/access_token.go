package token

import (
	"time"

	"github.com/google/uuid"
)

// AccessToken はアクセストークンのドメインエンティティ。
type AccessToken struct {
	id        uuid.UUID
	userID    uuid.UUID
	clientID  uuid.UUID
	tokenJTI  string
	scopes    string
	issuedAt  time.Time
	expiresAt time.Time
	revoked   bool
}

// NewAccessToken は AccessToken を生成する（永続化層からの再構築用）。
func NewAccessToken(id, userID, clientID uuid.UUID, tokenJTI, scopes string, issuedAt, expiresAt time.Time, revoked bool) *AccessToken {
	return &AccessToken{
		id:        id,
		userID:    userID,
		clientID:  clientID,
		tokenJTI:  tokenJTI,
		scopes:    scopes,
		issuedAt:  issuedAt,
		expiresAt: expiresAt,
		revoked:   revoked,
	}
}

func (t *AccessToken) ID() uuid.UUID        { return t.id }
func (t *AccessToken) UserID() uuid.UUID    { return t.userID }
func (t *AccessToken) ClientID() uuid.UUID  { return t.clientID }
func (t *AccessToken) TokenJTI() string     { return t.tokenJTI }
func (t *AccessToken) Scopes() string       { return t.scopes }
func (t *AccessToken) IssuedAt() time.Time  { return t.issuedAt }
func (t *AccessToken) ExpiresAt() time.Time { return t.expiresAt }
func (t *AccessToken) Revoked() bool        { return t.revoked }
