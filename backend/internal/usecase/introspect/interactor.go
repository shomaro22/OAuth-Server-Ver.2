package introspect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/port"
)

// UseCase はトークンイントロスペクトのユースケース。
// Interactor を実装する。
var _ Interactor = (*UseCase)(nil)

type UseCase struct {
	tokenRepo   port.TokenRepository
	sessionRepo port.SessionRepository
	jwtSigner   port.JWTSigner
}

// NewUseCase は UseCase を生成する。
func NewUseCase(tokenRepo port.TokenRepository, sessionRepo port.SessionRepository, jwtSigner port.JWTSigner) *UseCase {
	return &UseCase{
		tokenRepo:   tokenRepo,
		sessionRepo: sessionRepo,
		jwtSigner:   jwtSigner,
	}
}

// Introspect はトークンの有効性を検証し、claims を返す。
func (u *UseCase) Introspect(ctx context.Context, in *IntrospectInput) (*IntrospectOutput, error) {
	if in.Token == "" {
		return &IntrospectOutput{Active: false}, nil
	}

	// access_token (JWT) として試行
	if in.TokenTypeHint == "" || in.TokenTypeHint == "access_token" {
		if out := u.introspectAccessToken(ctx, in.Token); out != nil {
			return out, nil
		}
	}

	// refresh_token として試行
	if in.TokenTypeHint == "" || in.TokenTypeHint == "refresh_token" {
		if out := u.introspectRefreshToken(ctx, in.Token); out != nil {
			return out, nil
		}
	}

	return &IntrospectOutput{Active: false}, nil
}

func (u *UseCase) introspectAccessToken(ctx context.Context, tokenString string) *IntrospectOutput {
	claims, err := u.jwtSigner.Verify(tokenString)
	if err != nil || claims == nil {
		return nil
	}

	accessToken, err := u.tokenRepo.FindAccessTokenByJTI(ctx, claims.Jti)
	if err != nil || accessToken == nil {
		return &IntrospectOutput{Active: false}
	}
	if accessToken.Revoked() {
		return &IntrospectOutput{Active: false}
	}

	sid, err := uuid.Parse(claims.Sid)
	if err != nil {
		return &IntrospectOutput{Active: false}
	}
	sess, err := u.sessionRepo.FindByID(ctx, sid)
	if err != nil || sess == nil {
		return &IntrospectOutput{Active: false}
	}
	if sess.TokenVersion() != claims.Ver {
		return &IntrospectOutput{Active: false}
	}

	return &IntrospectOutput{
		Active:   true,
		Sub:      claims.Sub,
		Sid:      claims.Sid,
		Ver:      claims.Ver,
		Exp:      claims.Exp,
		Iat:      claims.Iat,
		ClientID: claims.Aud,
	}
}

func (u *UseCase) introspectRefreshToken(ctx context.Context, tokenString string) *IntrospectOutput {
	tokenHash := hashString(tokenString)
	refreshToken, err := u.tokenRepo.FindRefreshTokenByHash(ctx, tokenHash)
	if err != nil || refreshToken == nil {
		return nil
	}
	if refreshToken.Revoked() || refreshToken.Rotated() {
		return &IntrospectOutput{Active: false}
	}
	if time.Now().After(refreshToken.ExpiresAt()) {
		return &IntrospectOutput{Active: false}
	}

	accessToken, err := u.tokenRepo.FindAccessTokenByID(ctx, refreshToken.AccessTokenID())
	if err != nil || accessToken == nil {
		return &IntrospectOutput{Active: false}
	}
	if accessToken.Revoked() {
		return &IntrospectOutput{Active: false}
	}

	sess, err := u.sessionRepo.FindByID(ctx, accessToken.SessionID())
	if err != nil || sess == nil || sess.IsRevoked() {
		return &IntrospectOutput{Active: false}
	}

	return &IntrospectOutput{
		Active:   true,
		Sub:      accessToken.UserID().String(),
		Sid:      accessToken.SessionID().String(),
		Ver:      sess.TokenVersion(),
		ClientID: accessToken.ClientID().String(),
		Scope:    accessToken.Scopes(),
	}
}

func hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
