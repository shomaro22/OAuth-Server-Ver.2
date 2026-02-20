package router

import (
	"github.com/labstack/echo/v4"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/handler"
)

// Config はルーターの設定。
type Config struct {
	AuthorizeHandler  *handler.AuthorizeHandler
	TokenHandler      *handler.TokenHandler
	LoginHandler      *handler.LoginHandler
	LogoutHandler     *handler.LogoutHandler
	HealthHandler     *handler.HealthHandler
	DiscoveryHandler  *handler.DiscoveryHandler
	JWKSHandler       *handler.JWKSHandler
	UserInfoHandler   *handler.UserInfoHandler
}

// New はルーターを生成し、ルートを登録する。
func New(e *echo.Echo, cfg *Config) {
	e.GET("/health", cfg.HealthHandler.Get)

	e.GET("/.well-known/openid-configuration", cfg.DiscoveryHandler.Get)
	e.GET("/jwks", cfg.JWKSHandler.Get)

	e.POST("/sessions/login", cfg.LoginHandler.Post)
	e.POST("/sessions/logout", cfg.LogoutHandler.Post)

	e.GET("/oauth/authorize", cfg.AuthorizeHandler.Get)
	e.GET("/oauth/authorize/continue", cfg.AuthorizeHandler.GetContinue)
	e.GET("/oauth/authorize/deny", cfg.AuthorizeHandler.GetDeny)
	e.POST("/oauth/token", cfg.TokenHandler.Post)

	e.GET("/userinfo", cfg.UserInfoHandler.Get)
}
