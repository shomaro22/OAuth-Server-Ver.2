package logout

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	sessentity "github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/session"
)

type mockSessionRepo struct {
	findByHash *sessentity.Session
	findByErr  error
	revokeErr  error
	revokeCalled int
}

func (m *mockSessionRepo) Save(ctx context.Context, s *sessentity.Session) error { return nil }
func (m *mockSessionRepo) FindByID(ctx context.Context, sid uuid.UUID) (*sessentity.Session, error) {
	return nil, nil
}
func (m *mockSessionRepo) FindBySessionTokenHash(ctx context.Context, tokenHash string) (*sessentity.Session, error) {
	return m.findByHash, m.findByErr
}
func (m *mockSessionRepo) IncrementTokenVersion(ctx context.Context, sid uuid.UUID) error {
	return nil
}
func (m *mockSessionRepo) Revoke(ctx context.Context, sid uuid.UUID) error {
	m.revokeCalled++
	return m.revokeErr
}

func TestLogout_Success_RevokeCalled(t *testing.T) {
	sid := uuid.New()
	uid := uuid.New()
	sess := sessentity.Reconstruct(
		sid, uid, "hash", "127.0.0.1", "ua", 1,
		time.Now().Add(time.Hour), time.Now(), false,
	)

	repo := &mockSessionRepo{findByHash: sess}
	uc := NewUseCase(repo)

	err := uc.Logout(context.Background(), &LogoutInput{SessionToken: "valid-token"})
	if err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if repo.revokeCalled != 1 {
		t.Errorf("Revoke: want 1 call, got %d", repo.revokeCalled)
	}
}

func TestLogout_NoSession_ReturnsErrSessionNotFound(t *testing.T) {
	repo := &mockSessionRepo{findByHash: nil}
	uc := NewUseCase(repo)

	err := uc.Logout(context.Background(), &LogoutInput{SessionToken: "unknown-token"})
	if err != ErrSessionNotFound {
		t.Errorf("expected ErrSessionNotFound, got %v", err)
	}
	if repo.revokeCalled != 0 {
		t.Errorf("Revoke: want 0 calls, got %d", repo.revokeCalled)
	}
}

func TestLogout_RepoError_ReturnsError(t *testing.T) {
	sid := uuid.New()
	uid := uuid.New()
	sess := sessentity.Reconstruct(
		sid, uid, "hash", "127.0.0.1", "ua", 1,
		time.Now().Add(time.Hour), time.Now(), false,
	)

	repo := &mockSessionRepo{findByHash: sess, revokeErr: errors.New("db error")}
	uc := NewUseCase(repo)

	err := uc.Logout(context.Background(), &LogoutInput{SessionToken: "valid-token"})
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "db error" {
		t.Errorf("got %v", err)
	}
}
