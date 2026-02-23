package handler

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

// DiscoveryHandler は OIDC Discovery エンドポイントのハンドラ。
type DiscoveryHandler struct {
	issuer string
}

// NewDiscoveryHandler は DiscoveryHandler を生成する。
func NewDiscoveryHandler(issuer string) *DiscoveryHandler {
	return &DiscoveryHandler{issuer: issuer}
}

// Get は /.well-known/openid-configuration を返す。
// OIDC Discovery 1.0 のメタデータ。issuer を起点に全 URL を組み立てる。
func (h *DiscoveryHandler) Get(c echo.Context) error {
	base := strings.TrimSuffix(h.issuer, "/")
	return c.JSON(http.StatusOK, map[string]interface{}{
		// 識別子（ID Token の iss と完全一致 MUST）
		"issuer": base,

		// エンドポイント
		"authorization_endpoint": base + "/oauth/authorize",
		"token_endpoint":         base + "/oauth/token",
		"jwks_uri":               base + "/jwks",
		"userinfo_endpoint":      base + "/userinfo",

		// 機能サポート
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                []string{"authorization_code", "refresh_token"},
		"subject_types_supported":              []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":     []string{"S256"},

		// クライアント認証（PKCE 前提 + confidential 対応）
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_basic"},

		// スコープ・クレーム（実装と一致。UserInfo は常に sub, email, email_verified, preferred_username を返す）
		"scopes_supported": []string{"openid", "profile", "email"},
		"claims_supported": []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "sid", "email", "email_verified", "preferred_username"},
	})
}
