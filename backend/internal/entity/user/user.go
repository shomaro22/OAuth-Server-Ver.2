package user

import (
	"time"

	"github.com/google/uuid"
)

// User はユーザーのドメインエンティティ。
type User struct {
	id            uuid.UUID
	email         string
	username      string
	emailVerified bool
	status        string
	createdAt     time.Time
	updatedAt     time.Time
}

// NewUser は User を生成する（永続化層からの再構築用）。
func NewUser(id uuid.UUID, email, username string, emailVerified bool, status string, createdAt, updatedAt time.Time) *User {
	return &User{
		id:            id,
		email:         email,
		username:      username,
		emailVerified: emailVerified,
		status:        status,
		createdAt:     createdAt,
		updatedAt:     updatedAt,
	}
}

func (u *User) ID() uuid.UUID        { return u.id }
func (u *User) Email() string        { return u.email }
func (u *User) Username() string    { return u.username }
func (u *User) EmailVerified() bool { return u.emailVerified }
func (u *User) Status() string      { return u.status }
func (u *User) CreatedAt() time.Time { return u.createdAt }
func (u *User) UpdatedAt() time.Time { return u.updatedAt }
