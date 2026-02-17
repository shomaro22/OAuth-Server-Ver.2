package router

import (
	"github.com/labstack/echo/v4"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/handler"
)

// Config はルーターの設定。
type Config struct {
	AuthorizeHandler *handler.AuthorizeHandler
	TokenHandler     *handler.TokenHandler
	HealthHandler    *handler.HealthHandler
}

// New はルーターを生成し、ルートを登録する。
func New(e *echo.Echo, cfg *Config) {
	// Health
	e.GET("/health", cfg.HealthHandler.Get)

	// OAuth 2.0 / OIDC
	e.GET("/authorize", cfg.AuthorizeHandler.Get)
	e.POST("/authorize", cfg.AuthorizeHandler.Post)
	e.POST("/token", cfg.TokenHandler.Post)
}
