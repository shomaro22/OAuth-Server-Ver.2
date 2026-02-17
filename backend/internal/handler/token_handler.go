package handler

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// TokenHandler はトークンエンドポイントのハンドラ。
type TokenHandler struct{}

// NewTokenHandler は TokenHandler を生成する。
func NewTokenHandler() *TokenHandler {
	return &TokenHandler{}
}

// Post は認可コードをトークンに交換する。
// POST /token
func (h *TokenHandler) Post(c echo.Context) error {
	// TODO: grant_type=authorization_code の処理、PKCE検証、トークン発行
	return c.JSON(http.StatusOK, map[string]string{
		"message": "token POST - code to token exchange",
	})
}
