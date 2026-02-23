package session

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	sessentity "github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/session"
)

type mockSessionRepo struct {
	findByHash *sessentity.Session
	findByErr  error
}

func (m *mockSessionRepo) Save(ctx context.Context, s *sessentity.Session) error { return nil }
func (m *mockSessionRepo) FindByID(ctx context.Context, sid uuid.UUID) (*sessentity.Session, error) {
	return nil, nil
}
func (m *mockSessionRepo) FindBySessionTokenHash(ctx context.Context, tokenHash string) (*sessentity.Session, error) {
	return m.findByHash, m.findByErr
}
func (m *mockSessionRepo) IncrementTokenVersion(ctx context.Context, sid uuid.UUID) error { return nil }
func (m *mockSessionRepo) Revoke(ctx context.Context, sid uuid.UUID) error                { return nil }

func TestResolve_NoCookie_ReturnsNoSession(t *testing.T) {
	r := NewResolver(&mockSessionRepo{})

	sid, uid, ok, err := r.Resolve(context.Background(), "")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected ok=false for empty token")
	}
	if sid != uuid.Nil || uid != uuid.Nil {
		t.Errorf("expected Nil IDs, got sid=%v uid=%v", sid, uid)
	}
}

func TestResolve_SessionNotFound_ReturnsNoSession(t *testing.T) {
	r := NewResolver(&mockSessionRepo{findByHash: nil, findByErr: nil})

	sid, uid, ok, err := r.Resolve(context.Background(), "any-token")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected ok=false for session not found")
	}
	if sid != uuid.Nil || uid != uuid.Nil {
		t.Errorf("expected Nil IDs, got sid=%v uid=%v", sid, uid)
	}
}

func TestResolve_SessionExpired_ReturnsNoSession(t *testing.T) {
	sid := uuid.New()
	uid := uuid.New()
	expired := sessentity.Reconstruct(
		sid, uid, "hash", "127.0.0.1", "ua", 1,
		time.Now().Add(-time.Hour), time.Now().Add(-2*time.Hour), false,
	)
	r := NewResolver(&mockSessionRepo{findByHash: expired})

	_, _, ok, err := r.Resolve(context.Background(), "token")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected ok=false for expired session")
	}
}

func TestResolve_Success_ReturnsSession(t *testing.T) {
	sid := uuid.New()
	uid := uuid.New()
	sess := sessentity.Reconstruct(
		sid, uid, "hash", "127.0.0.1", "ua", 1,
		time.Now().Add(time.Hour), time.Now(), false,
	)
	r := NewResolver(&mockSessionRepo{findByHash: sess})

	gotSid, gotUid, ok, err := r.Resolve(context.Background(), "valid-token")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected ok=true")
	}
	if gotSid != sid || gotUid != uid {
		t.Errorf("got sid=%v uid=%v, want sid=%v uid=%v", gotSid, gotUid, sid, uid)
	}
}
