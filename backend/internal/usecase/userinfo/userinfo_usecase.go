package userinfo

import (
	"context"
	"errors"
	"time"

	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/port"
)

var (
	ErrInvalidToken = errors.New("invalid access token")
)

// UseCase はユーザー情報取得のユースケース。
type UseCase struct {
	tokenRepo port.TokenRepository
	userRepo  port.UserRepository
}

// NewUseCase は UseCase を生成する。
func NewUseCase(tokenRepo port.TokenRepository, userRepo port.UserRepository) *UseCase {
	return &UseCase{
		tokenRepo: tokenRepo,
		userRepo:  userRepo,
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

// Get はアクセストークンからユーザー情報を取得する。
func (u *UseCase) Get(ctx context.Context, in *GetInput) (*GetOutput, error) {
	// 1. アクセストークン検証
	accessToken, err := u.tokenRepo.FindAccessTokenByJTI(ctx, in.AccessToken)
	if err != nil || accessToken == nil {
		return nil, ErrInvalidToken
	}

	if accessToken.Revoked() {
		return nil, ErrInvalidToken
	}

	if time.Now().After(accessToken.ExpiresAt()) {
		return nil, ErrInvalidToken
	}

	// 2. ユーザー情報取得
	usr, err := u.userRepo.FindByID(ctx, accessToken.UserID())
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
