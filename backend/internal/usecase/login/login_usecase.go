package login

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/entity/session"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/port"
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrChallengeNotFound  = errors.New("login challenge not found or expired")
)

const sessionExpiryHours = 24

// UseCase はログインのユースケース。
type UseCase struct {
	userRepo      port.UserRepository
	sessionRepo   port.SessionRepository
	authReqRepo   port.AuthorizationRequestRepository
	serverBaseURL string

	secureToken func() (string, error) // テスト用に差し替え可能（デフォルト: generateSecureToken）
}

// NewUseCase は UseCase を生成する。
func NewUseCase(
	userRepo port.UserRepository,
	sessionRepo port.SessionRepository,
	authReqRepo port.AuthorizationRequestRepository,
	serverBaseURL string,
) *UseCase {
	return &UseCase{
		userRepo:      userRepo,
		sessionRepo:   sessionRepo,
		authReqRepo:   authReqRepo,
		serverBaseURL: serverBaseURL,
		secureToken:   generateSecureToken,
	}
}

// LoginInput はログインの入力。
type LoginInput struct {
	LoginChallenge string
	Username       string
	Password       string
	IPAddress      string
	UserAgent      string
}

// LoginOutput はログインの出力。
type LoginOutput struct {
	NextURL      string
	SessionToken string
}

// Login はユーザー認証を行い、セッションを作成して next_url を返す。
func (u *UseCase) Login(ctx context.Context, in *LoginInput) (*LoginOutput, error) {
	if in.LoginChallenge == "" || in.Username == "" || in.Password == "" {
		return nil, ErrInvalidCredentials
	}

	req, err := u.authReqRepo.Get(ctx, in.LoginChallenge)
	if err != nil {
		return nil, fmt.Errorf("get auth request: %w", err)
	}
	if req == nil {
		return nil, ErrChallengeNotFound
	}

	user, passwordHash, err := u.userRepo.FindByUsername(ctx, in.Username)
	if err != nil {
		return nil, fmt.Errorf("find user: %w", err)
	}
	if user == nil || passwordHash == "" {
		return nil, ErrInvalidCredentials
	}
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(in.Password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	gen := u.secureToken
	if gen == nil {
		gen = generateSecureToken
	}
	token, err := gen()
	if err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}
	tokenHash := hashString(token)

	expiresAt := time.Now().Add(sessionExpiryHours * time.Hour)
	sess := session.New(
		user.ID(),
		tokenHash,
		in.IPAddress,
		in.UserAgent,
		1,
		expiresAt,
	)
	if err := u.sessionRepo.Save(ctx, sess); err != nil {
		return nil, fmt.Errorf("save session: %w", err)
	}

	nextURL := u.serverBaseURL + "/oauth/authorize/continue?login_challenge=" + in.LoginChallenge

	return &LoginOutput{
		NextURL:      nextURL,
		SessionToken: token,
	}, nil
}

func generateSecureToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b), nil
}

func hashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
