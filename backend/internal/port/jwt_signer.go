package port

import (
	"time"

	"github.com/google/uuid"
)

// AccessTokenClaims は JWT 検証後の claims（port 層で定義して usecase が依存）。
type AccessTokenClaims struct {
	Sub string // user_id
	Sid string // session_id
	Ver int64  // token_version
	Aud string // client_id
	Jti string // token id
	Exp int64  // 有効期限（Unix秒）
	Iat int64  // 発行日時（Unix秒）
}

// JWTSigner は JWT の署名・検証インターフェース。
type JWTSigner interface {
	Sign(sub, sid, aud uuid.UUID, ver int64, jti string, expiresIn time.Duration) (string, error)
	SignIDToken(iss, sub, aud string, nonce string, authTime time.Time, expiresIn time.Duration) (string, error)
	Verify(tokenString string) (*AccessTokenClaims, error)
}
