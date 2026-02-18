package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/port"
)

// accessTokenClaims は JWT 内部の claims 構造。
// sub/aud は RegisteredClaims に含まれるため重複しない。
type accessTokenClaims struct {
	jwt.RegisteredClaims
	Sid string `json:"sid"`
	Ver int64  `json:"ver"`
}

// Signer は RS256 で JWT を署名する。
type Signer struct {
	privateKey *rsa.PrivateKey
}

// NewSigner は秘密鍵から Signer を生成する。
func NewSigner(privateKey *rsa.PrivateKey) *Signer {
	return &Signer{privateKey: privateKey}
}

// GenerateKey は開発用の RSA 秘密鍵を生成する。
func GenerateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// ParsePrivateKey は PEM 形式の秘密鍵をパースする。
func ParsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return key, nil
}

// Sign はアクセストークン JWT を署名して返す。
func (s *Signer) Sign(sub, sid, aud uuid.UUID, ver int64, jti string, expiresIn time.Duration) (string, error) {
	now := time.Now()
	claims := accessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Subject:   sub.String(),
			Audience:  jwt.ClaimStrings{aud.String()},
			ExpiresAt: jwt.NewNumericDate(now.Add(expiresIn)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		Sid: sid.String(),
		Ver: ver,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(s.privateKey)
}

// Verify は JWT を検証し claims を返す。
func (s *Signer) Verify(tokenString string) (*port.AccessTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &accessTokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return &s.privateKey.PublicKey, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*accessTokenClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	aud, _ := claims.GetAudience()
	audStr := ""
	if len(aud) > 0 {
		audStr = aud[0]
	}
	return &port.AccessTokenClaims{
		Sub: claims.Subject,
		Sid: claims.Sid,
		Ver: claims.Ver,
		Aud: audStr,
		Jti: claims.ID,
	}, nil
}
