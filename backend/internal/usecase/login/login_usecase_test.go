package login

import (
	"context"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/google/uuid"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/user"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/port"
	sessentity "github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/session"
)

type mockUserRepo struct {
	user         *user.User
	passwordHash string
	err          error
}

func (m *mockUserRepo) FindByID(ctx context.Context, id uuid.UUID) (*user.User, error) {
	return nil, nil
}

func (m *mockUserRepo) FindByUsername(ctx context.Context, username string) (*user.User, string, error) {
	return m.user, m.passwordHash, m.err
}

func (m *mockUserRepo) Save(ctx context.Context, u *user.User) error {
	return nil
}

type mockSessionRepo struct {
	saveErr error
	saveCalled int
}

func (m *mockSessionRepo) Save(ctx context.Context, s *sessentity.Session) error {
	m.saveCalled++
	return m.saveErr
}

func (m *mockSessionRepo) FindByID(ctx context.Context, sid uuid.UUID) (*sessentity.Session, error) {
	return nil, nil
}

func (m *mockSessionRepo) FindBySessionTokenHash(ctx context.Context, tokenHash string) (*sessentity.Session, error) {
	return nil, nil
}

func (m *mockSessionRepo) IncrementTokenVersion(ctx context.Context, sid uuid.UUID) error {
	return nil
}

func (m *mockSessionRepo) Revoke(ctx context.Context, sid uuid.UUID) error {
	return nil
}

type mockAuthReqRepo struct {
	req *port.StoredAuthorizationRequest
	err error
}

func (m *mockAuthReqRepo) Save(ctx context.Context, challenge string, req *port.StoredAuthorizationRequest, ttl time.Duration) error {
	return nil
}

func (m *mockAuthReqRepo) Get(ctx context.Context, challenge string) (*port.StoredAuthorizationRequest, error) {
	return m.req, m.err
}

func (m *mockAuthReqRepo) Delete(ctx context.Context, challenge string) error {
	return nil
}

// TestLogin_Success_GenerateSecureToken は generateSecureToken を踏む正常系（注入なし）。
func TestLogin_Success_GenerateSecureToken(t *testing.T) {
	uid := uuid.New()
	hash, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	u := user.NewUser(uid, "a@b.com", "testuser", true, "active", time.Now(), time.Now())

	userRepo := &mockUserRepo{user: u, passwordHash: string(hash)}
	sessRepo := &mockSessionRepo{}
	authRepo := &mockAuthReqRepo{req: &port.StoredAuthorizationRequest{ClientID: "c", RedirectURI: "https://example.com/cb"}}

	uc := NewUseCase(userRepo, sessRepo, authRepo, "https://server")
	// secureToken を注入しない → 実装の generateSecureToken が呼ばれる

	out, err := uc.Login(context.Background(), &LoginInput{
		LoginChallenge: "ch123",
		Username:       "testuser",
		Password:       "password123",
		IPAddress:      "127.0.0.1",
		UserAgent:      "test",
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if out.SessionToken == "" {
		t.Error("SessionToken should not be empty")
	}
	if sessRepo.saveCalled != 1 {
		t.Errorf("sessionRepo.Save: want 1 call, got %d", sessRepo.saveCalled)
	}
}

func TestLogin_Success_CreatesSessionAndReturnsToken(t *testing.T) {
	uid := uuid.New()
	hash, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	u := user.NewUser(uid, "a@b.com", "testuser", true, "active", time.Now(), time.Now())

	userRepo := &mockUserRepo{user: u, passwordHash: string(hash)}
	sessRepo := &mockSessionRepo{}
	authRepo := &mockAuthReqRepo{req: &port.StoredAuthorizationRequest{ClientID: "c", RedirectURI: "https://example.com/cb"}}

	uc := NewUseCase(userRepo, sessRepo, authRepo, "https://server")
	uc.secureToken = func() (string, error) { return "session-token-xyz", nil }

	out, err := uc.Login(context.Background(), &LoginInput{
		LoginChallenge: "ch123",
		Username:       "testuser",
		Password:       "password123",
		IPAddress:      "127.0.0.1",
		UserAgent:      "test",
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if out.SessionToken != "session-token-xyz" {
		t.Errorf("SessionToken=%q, want session-token-xyz", out.SessionToken)
	}
	if out.NextURL != "https://server/oauth/authorize/continue?login_challenge=ch123" {
		t.Errorf("NextURL=%q", out.NextURL)
	}
	if sessRepo.saveCalled != 1 {
		t.Errorf("sessionRepo.Save: want 1 call, got %d", sessRepo.saveCalled)
	}
}

func TestLogin_InvalidCredentials_PasswordMismatch(t *testing.T) {
	uid := uuid.New()
	hash, _ := bcrypt.GenerateFromPassword([]byte("correct"), bcrypt.DefaultCost)
	u := user.NewUser(uid, "a@b.com", "testuser", true, "active", time.Now(), time.Now())

	userRepo := &mockUserRepo{user: u, passwordHash: string(hash)}
	sessRepo := &mockSessionRepo{}
	authRepo := &mockAuthReqRepo{req: &port.StoredAuthorizationRequest{}}

	uc := NewUseCase(userRepo, sessRepo, authRepo, "https://server")

	_, err := uc.Login(context.Background(), &LoginInput{
		LoginChallenge: "ch123",
		Username:       "testuser",
		Password:       "wrong",
		IPAddress:      "127.0.0.1",
		UserAgent:      "test",
	})
	if err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
	if sessRepo.saveCalled != 0 {
		t.Errorf("sessionRepo.Save: want 0 calls, got %d", sessRepo.saveCalled)
	}
}

func TestLogin_UserNotFound_ReturnsErrInvalidCredentials(t *testing.T) {
	userRepo := &mockUserRepo{user: nil, passwordHash: ""}
	sessRepo := &mockSessionRepo{}
	authRepo := &mockAuthReqRepo{req: &port.StoredAuthorizationRequest{}}

	uc := NewUseCase(userRepo, sessRepo, authRepo, "https://server")

	_, err := uc.Login(context.Background(), &LoginInput{
		LoginChallenge: "ch123",
		Username:       "nobody",
		Password:       "any",
		IPAddress:      "127.0.0.1",
		UserAgent:      "test",
	})
	if err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
	if sessRepo.saveCalled != 0 {
		t.Errorf("sessionRepo.Save: want 0 calls, got %d", sessRepo.saveCalled)
	}
}
