package router

import (
	"github.com/labstack/echo/v4"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/handler"
)

// Config はルーターの設定。
// Step4 完了までは authorize / token / login / health のみ。
type Config struct {
	AuthorizeHandler *handler.AuthorizeHandler
	TokenHandler     *handler.TokenHandler
	LoginHandler     *handler.LoginHandler
	HealthHandler    *handler.HealthHandler
}

// New はルーターを生成し、ルートを登録する。
func New(e *echo.Echo, cfg *Config) {
	e.GET("/health", cfg.HealthHandler.Get)

	e.POST("/sessions/login", cfg.LoginHandler.Post)

	e.GET("/oauth/authorize", cfg.AuthorizeHandler.Get)
	e.GET("/oauth/authorize/continue", cfg.AuthorizeHandler.GetContinue)
	e.POST("/oauth/token", cfg.TokenHandler.Post)
}
