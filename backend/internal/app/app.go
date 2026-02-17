package app

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/infrastructure/database"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/repository"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/usecase/authorize"
)

// App はアプリケーションの組み立てと起動を担当する。
type App struct {
	pool *pgxpool.Pool
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
	_ = authorize.NewUseCase(authCodeRepo, sessionRepo, clientRepo)
	// TODO: Router に authorizeUseCase を渡して起動

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down...")
	return nil
}

// Close はリソースを解放する。
func (a *App) Close() {
	if a.pool != nil {
		a.pool.Close()
	}
}

