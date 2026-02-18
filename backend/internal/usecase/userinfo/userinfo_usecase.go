package userinfo

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/port"
)

var (
	ErrInvalidToken = errors.New("invalid access token")
)

// UseCase はユーザー情報取得のユースケース。
// Interactor を実装する。
var _ Interactor = (*UseCase)(nil)

type UseCase struct {
	tokenRepo   port.TokenRepository
	userRepo    port.UserRepository
	sessionRepo port.SessionRepository
	jwtSigner   port.JWTSigner
}

// NewUseCase は UseCase を生成する。
func NewUseCase(tokenRepo port.TokenRepository, userRepo port.UserRepository, sessionRepo port.SessionRepository, jwtSigner port.JWTSigner) *UseCase {
	return &UseCase{
		tokenRepo:   tokenRepo,
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		jwtSigner:   jwtSigner,
	}
}

// GetInput はユーザー情報取得の入力。
type GetInput struct {
	AccessToken string
}

// GetOutput はユーザー情報の出力（OIDC UserInfo 形式）。
type GetOutput struct {
	Sub            string `json:"sub"`
	Email          string `json:"email,omitempty"`
	EmailVerified  bool   `json:"email_verified,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
}

// Get はアクセストークン（JWT）からユーザー情報を取得する。
func (u *UseCase) Get(ctx context.Context, in *GetInput) (*GetOutput, error) {
	// 1. JWT 検証（署名・有効期限）
	claims, err := u.jwtSigner.Verify(in.AccessToken)
	if err != nil || claims == nil {
		return nil, ErrInvalidToken
	}

	// 2. access_token の失効チェック（jti で検索）
	accessToken, err := u.tokenRepo.FindAccessTokenByJTI(ctx, claims.Jti)
	if err != nil || accessToken == nil {
		return nil, ErrInvalidToken
	}
	if accessToken.Revoked() {
		return nil, ErrInvalidToken
	}

	// 3. Token Version 照合（sid → session → ver）
	sid, err := uuid.Parse(claims.Sid)
	if err != nil {
		return nil, ErrInvalidToken
	}
	sess, err := u.sessionRepo.FindByID(ctx, sid)
	if err != nil || sess == nil {
		return nil, ErrInvalidToken
	}
	if sess.TokenVersion() != claims.Ver {
		return nil, ErrInvalidToken
	}

	// 4. ユーザー情報取得
	userID, err := uuid.Parse(claims.Sub)
	if err != nil {
		return nil, ErrInvalidToken
	}
	usr, err := u.userRepo.FindByID(ctx, userID)
	if err != nil || usr == nil {
		return nil, ErrInvalidToken
	}

	return &GetOutput{
		Sub:               usr.ID().String(),
		Email:             usr.Email(),
		EmailVerified:     usr.EmailVerified(),
		PreferredUsername: usr.Username(),
	}, nil
}
