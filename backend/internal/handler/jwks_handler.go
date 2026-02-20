package handler

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/port"
)

// JWKSHandler は JWKS エンドポイントのハンドラ。
type JWKSHandler struct {
	jwksProvider port.JWKSProvider
}

// NewJWKSHandler は JWKSHandler を生成する。
func NewJWKSHandler(jwksProvider port.JWKSProvider) *JWKSHandler {
	return &JWKSHandler{jwksProvider: jwksProvider}
}

// Get は /jwks で公開鍵を返す。
// RFC 7517 JWK Set。kid は JWT ヘッダと一致。Cache-Control で 1 時間キャッシュ推奨。
func (h *JWKSHandler) Get(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "public, max-age=3600")
	return c.JSON(http.StatusOK, h.jwksProvider.ExportJWKS())
}
