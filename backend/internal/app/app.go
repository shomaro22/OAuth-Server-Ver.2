package app

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/handler"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/infrastructure/database"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/repository"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/router"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/usecase/authorize"
)

// App はアプリケーションの組み立てと起動を担当する。
type App struct {
	pool *pgxpool.Pool
	e    *echo.Echo
}

// New は App を生成する。DI の入口。
func New() (*App, error) {
	// DB接続（タイムアウト付き：DBが死んでると起動が無限待ちになるのを防ぐ）
	ctx, cancel := context.WithTimeout(context.Background(), database.DefaultConnectTimeout*time.Second)
	defer cancel()

	cfg := database.NewConfig()
	pool, err := database.NewPool(ctx, cfg)
	if err != nil {
		return nil, err
	}

	log.Println("Successfully connected to PostgreSQL")

	return &App{pool: pool}, nil
}

// Run はアプリケーションを起動する。
func (a *App) Run() error {
	// Repository 生成
	authCodeRepo := repository.NewPostgresAuthCodeRepository(a.pool)
	sessionRepo := repository.NewPostgresSessionRepository(a.pool)
	clientRepo := repository.NewPostgresClientRepository(a.pool)

	// Usecase 生成
	authorizeUseCase := authorize.NewUseCase(authCodeRepo, sessionRepo, clientRepo)

	// Handler 生成
	authorizeHandler := handler.NewAuthorizeHandler(authorizeUseCase)
	tokenHandler := handler.NewTokenHandler()
	healthHandler := handler.NewHealthHandler()

	// Router 生成・登録
	port := getEnv("SERVER_PORT", "8080")
	a.e = echo.New()
	router.New(a.e, &router.Config{
		AuthorizeHandler: authorizeHandler,
		TokenHandler:     tokenHandler,
		HealthHandler:    healthHandler,
	})

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down...")
		if err := a.e.Shutdown(context.Background()); err != nil {
			log.Printf("Shutdown error: %v", err)
		}
	}()

	addr := fmt.Sprintf(":%s", port)
	log.Printf("Server starting on %s", addr)
	return a.e.Start(addr)
}

func getEnv(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

// Close はリソースを解放する。
func (a *App) Close() {
	if a.pool != nil {
		a.pool.Close()
	}
}

