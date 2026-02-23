package user

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNewUser(t *testing.T) {
	id := uuid.New()
	now := time.Now()

	u := NewUser(id, "a@b.com", "testuser", true, "active", now, now)

	if u.ID() != id {
		t.Errorf("ID: got %v", u.ID())
	}
	if u.Email() != "a@b.com" || u.Username() != "testuser" {
		t.Errorf("Email/Username: got %s / %s", u.Email(), u.Username())
	}
	if !u.EmailVerified() || u.Status() != "active" {
		t.Errorf("EmailVerified/Status: got %v / %s", u.EmailVerified(), u.Status())
	}
	if u.CreatedAt() != now || u.UpdatedAt() != now {
		t.Error("CreatedAt/UpdatedAt mismatch")
	}
}
