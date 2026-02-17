package handler

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// HealthHandler はヘルスチェック用ハンドラ。
type HealthHandler struct{}

// NewHealthHandler は HealthHandler を生成する。
func NewHealthHandler() *HealthHandler {
	return &HealthHandler{}
}

// Get はヘルスチェックを返す。
// GET /health
func (h *HealthHandler) Get(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{
		"status": "ok",
	})
}
