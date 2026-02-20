package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/port"
)

const defaultKeyID = "default"

// accessTokenClaims は JWT 内部の claims 構造。
// sub/aud は RegisteredClaims に含まれるため重複しない。
type accessTokenClaims struct {
	jwt.RegisteredClaims
	Sid string `json:"sid"`
	Ver int64  `json:"ver"`
}

// Signer は RS256 で JWT を署名する。port.JWTSigner と port.JWKSProvider を実装する。
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

// idTokenClaims は ID Token の claims 構造。
type idTokenClaims struct {
	jwt.RegisteredClaims
	AuthTime *jwt.NumericDate `json:"auth_time"`
	Nonce   string            `json:"nonce,omitempty"`
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
	token.Header["kid"] = defaultKeyID
	return token.SignedString(s.privateKey)
}

// SignIDToken は ID Token JWT を署名して返す。
// iss, sub, aud, exp, iat, auth_time, nonce を含む。
func (s *Signer) SignIDToken(iss, sub, aud string, nonce string, authTime time.Time, expiresIn time.Duration) (string, error) {
	now := time.Now()
	claims := idTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    iss,
			Subject:   sub,
			Audience:  jwt.ClaimStrings{aud},
			ExpiresAt: jwt.NewNumericDate(now.Add(expiresIn)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		AuthTime: jwt.NewNumericDate(authTime),
		Nonce:    nonce,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = defaultKeyID
	return token.SignedString(s.privateKey)
}

// JWKS は JSON Web Key Set の構造。
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK は JSON Web Key の構造（RSA 用）。
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// ExportJWKS は公開鍵を JWKS 形式で返す。port.JWKSProvider を実装する。
func (s *Signer) ExportJWKS() any {
	return s.exportJWKS()
}

func (s *Signer) exportJWKS() *JWKS {
	pub := s.privateKey.Public().(*rsa.PublicKey)
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	return &JWKS{
		Keys: []JWK{
			{Kty: "RSA", Kid: defaultKeyID, Use: "sig", Alg: "RS256", N: n, E: e},
		},
	}
}

// ExportJWKSJSON は JWKS を JSON 文字列で返す。
func (s *Signer) ExportJWKSJSON() (string, error) {
	b, err := json.Marshal(s.exportJWKS())
	if err != nil {
		return "", err
	}
	return string(b), nil
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
	exp := int64(0)
	if claims.ExpiresAt != nil {
		exp = claims.ExpiresAt.Unix()
	}
	iat := int64(0)
	if claims.IssuedAt != nil {
		iat = claims.IssuedAt.Unix()
	}
	return &port.AccessTokenClaims{
		Sub: claims.Subject,
		Sid: claims.Sid,
		Ver: claims.Ver,
		Aud: audStr,
		Jti: claims.ID,
		Exp: exp,
		Iat: iat,
	}, nil
}
