package app

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/labstack/echo/v4"
	"gorm.io/gorm"

	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/handler"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/infrastructure/db"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/infrastructure/jwt"
	gormrepo "github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/infrastructure/repository/gorm"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/router"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/usecase/authorize"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/usecase/introspect"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/usecase/logout"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/usecase/token"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/usecase/userinfo"
)

// App はアプリケーションの組み立てと起動を担当する。
type App struct {
	db *gorm.DB
	e  *echo.Echo
}

// New は App を生成する。DI の入口。
func New() (*App, error) {
	cfg := db.NewConfig()
	gormDB, err := db.NewDB(cfg)
	if err != nil {
		return nil, err
	}

	log.Println("Successfully connected to PostgreSQL (GORM)")

	return &App{db: gormDB}, nil
}

// Run はアプリケーションを起動する。
func (a *App) Run() error {
	// Repository 生成（port を実装する GORM adapter）
	authCodeRepo := gormrepo.NewAuthCodeRepository(a.db)
	sessionRepo := gormrepo.NewSessionRepository(a.db)
	clientRepo := gormrepo.NewClientRepository(a.db)
	tokenRepo := gormrepo.NewTokenRepository(a.db)
	userRepo := gormrepo.NewUserRepository(a.db)

	// JWT Signer（RS256、開発用は起動時に鍵生成）
	jwtKey, err := jwt.GenerateKey()
	if err != nil {
		return fmt.Errorf("generate jwt key: %w", err)
	}
	jwtSigner := jwt.NewSigner(jwtKey)

	// TransactionRunner（code 交換の二重実行防止用）
	txRunner := db.NewTransactionRunner(a.db)

	// Issuer（ID Token の iss claim、環境変数で上書き可能）
	issuer := getEnv("OAUTH_ISSUER", "https://localhost:8080")

	// Usecase 生成
	authorizeUseCase := authorize.NewUseCase(authCodeRepo, sessionRepo, clientRepo)
	tokenUseCase := token.NewUseCase(txRunner, authCodeRepo, tokenRepo, clientRepo, sessionRepo, jwtSigner, issuer)
	userInfoUseCase := userinfo.NewUseCase(tokenRepo, userRepo, sessionRepo, jwtSigner)
	logoutUseCase := logout.NewUseCase(sessionRepo)
	introspectUseCase := introspect.NewUseCase(tokenRepo, sessionRepo, jwtSigner)

	// Handler 生成
	authorizeHandler := handler.NewAuthorizeHandler(authorizeUseCase)
	tokenHandler := handler.NewTokenHandler(tokenUseCase)
	userInfoHandler := handler.NewUserInfoHandler(userInfoUseCase)
	logoutHandler := handler.NewLogoutHandler(logoutUseCase)
	introspectHandler := handler.NewIntrospectHandler(introspectUseCase, clientRepo)
	healthHandler := handler.NewHealthHandler()

	// Router 生成・登録
	port := getEnv("SERVER_PORT", "8080")
	a.e = echo.New()
	router.New(a.e, &router.Config{
		AuthorizeHandler:   authorizeHandler,
		TokenHandler:       tokenHandler,
		UserInfoHandler:    userInfoHandler,
		LogoutHandler:      logoutHandler,
		IntrospectHandler:  introspectHandler,
		HealthHandler:      healthHandler,
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
	if a.db != nil {
		if sqlDB, err := a.db.DB(); err == nil {
			sqlDB.Close()
		}
	}
}

