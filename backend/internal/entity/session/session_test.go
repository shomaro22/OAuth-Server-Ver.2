package session

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSession_IsExpired(t *testing.T) {
	expiresAt := time.Now().Add(-time.Hour) // 1時間前に期限切れ
	s := New(
		uuid.New(),
		"hash",
		"127.0.0.1",
		"Mozilla",
		1,
		expiresAt,
	)

	if !s.IsExpired(time.Now()) {
		t.Error("IsExpired: expected true for expired session")
	}
}

func TestSession_IsValid(t *testing.T) {
	expiresAt := time.Now().Add(time.Hour)
	s := New(
		uuid.New(),
		"hash",
		"127.0.0.1",
		"Mozilla",
		1,
		expiresAt,
	)

	if !s.IsValid(time.Now()) {
		t.Error("IsValid: expected true for valid session")
	}

	s.Revoke()
	if s.IsValid(time.Now()) {
		t.Error("IsValid: expected false after Revoke")
	}
}

func TestSession_IncrementVersion(t *testing.T) {
	s := New(
		uuid.New(),
		"hash",
		"127.0.0.1",
		"Mozilla",
		1,
		time.Now().Add(time.Hour),
	)

	if s.TokenVersion() != 1 {
		t.Errorf("TokenVersion: expected 1, got %d", s.TokenVersion())
	}

	s.IncrementVersion()
	if s.TokenVersion() != 2 {
		t.Errorf("TokenVersion after IncrementVersion: expected 2, got %d", s.TokenVersion())
	}
}

func TestReconstruct(t *testing.T) {
	id := uuid.New()
	uid := uuid.New()
	expiresAt := time.Now().Add(time.Hour)
	createdAt := time.Now()

	s := Reconstruct(id, uid, "hash", "1.2.3.4", "Agent", 2, expiresAt, createdAt, true)

	if s.ID() != id || s.UserID() != uid || s.SessionTokenHash() != "hash" {
		t.Error("Reconstruct: IDs/hash mismatch")
	}
	if s.TokenVersion() != 2 || !s.IsRevoked() {
		t.Error("Reconstruct: version/revoked mismatch")
	}
}
