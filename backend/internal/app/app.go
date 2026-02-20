package app

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	redis "github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/handler"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/infrastructure/db"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/infrastructure/jwt"
	redisinfra "github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/infrastructure/redis"
	gormrepo "github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/infrastructure/repository/gorm"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/router"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/usecase/authorize"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/usecase/login"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/usecase/logout"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/usecase/session"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/usecase/token"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/usecase/userinfo"
)

// App はアプリケーションの組み立てと起動を担当する。
type App struct {
	db    *gorm.DB
	redis *redis.Client
	e     *echo.Echo
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

	// Redis（login_challenge 用）
	redisCfg := redisinfra.NewConfig()
	redisClient, err := redisinfra.NewClient(redisCfg)
	if err != nil {
		return fmt.Errorf("redis: %w", err)
	}
	a.redis = redisClient
	authReqRepo := redisinfra.NewAuthorizationRequestRepository(redisClient)

	// JWT Signer（RS256、開発用は起動時に鍵生成）
	jwtKey, err := jwt.GenerateKey()
	if err != nil {
		return fmt.Errorf("generate jwt key: %w", err)
	}
	jwtSigner := jwt.NewSigner(jwtKey)

	// TransactionRunner（code 交換の二重実行防止用）
	txRunner := db.NewTransactionRunner(a.db)

	// Issuer（ID Token の iss、Discovery、全 endpoint URL の起点。本番は https 必須）
	issuer := getEnv("OAUTH_ISSUER", "http://localhost:8080")

	// ログイン/認可URL（環境変数で上書き可能）
	loginURL := getEnv("LOGIN_URL", "http://localhost:5173/login")
	consentURL := getEnv("CONSENT_URL", "http://localhost:5173/consent")
	serverBaseURL := getEnv("SERVER_BASE_URL", "http://localhost:8080")

	// CORS: React（別オリジン）から credentials 付きで Cookie を受け取るために必須
	// AllowCredentials=true のとき AllowOrigins は * 不可。CORS_ORIGIN でフロントのオリジンを指定。
	corsOrigin := getEnv("CORS_ORIGIN", "http://localhost:5173")

	// Usecase 生成
	authorizeUseCase := authorize.NewUseCase(authCodeRepo, clientRepo, authReqRepo)
	sessionResolver := session.NewResolver(sessionRepo)
	tokenUseCase := token.NewUseCase(txRunner, authCodeRepo, tokenRepo, clientRepo, sessionRepo, jwtSigner, issuer)
	loginUseCase := login.NewUseCase(userRepo, sessionRepo, authReqRepo, serverBaseURL)
	logoutUseCase := logout.NewUseCase(sessionRepo)
	userInfoUseCase := userinfo.NewUseCase(tokenRepo, userRepo, sessionRepo, jwtSigner)

	// Handler 生成
	authorizeHandler := handler.NewAuthorizeHandler(authorizeUseCase, sessionResolver, loginURL, consentURL, serverBaseURL)
	tokenHandler := handler.NewTokenHandler(tokenUseCase, clientRepo, []string{corsOrigin})
	loginHandler := handler.NewLoginHandler(loginUseCase)
	logoutHandler := handler.NewLogoutHandler(logoutUseCase)
	healthHandler := handler.NewHealthHandler()
	discoveryHandler := handler.NewDiscoveryHandler(issuer)
	jwksHandler := handler.NewJWKSHandler(jwtSigner) // *jwt.Signer は port.JWKSProvider を実装
	userInfoHandler := handler.NewUserInfoHandler(userInfoUseCase)

	port := getEnv("SERVER_PORT", "8080")
	a.e = echo.New()

	// CORS: credentials 付きリクエストで Cookie を返すために必須
	a.e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     []string{corsOrigin},
		AllowMethods:     []string{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
	}))

	router.New(a.e, &router.Config{
		AuthorizeHandler: authorizeHandler,
		TokenHandler:     tokenHandler,
		LoginHandler:     loginHandler,
		LogoutHandler:    logoutHandler,
		HealthHandler:    healthHandler,
		DiscoveryHandler: discoveryHandler,
		JWKSHandler:      jwksHandler,
		UserInfoHandler:  userInfoHandler,
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
	if a.redis != nil {
		a.redis.Close()
	}
	if a.db != nil {
		if sqlDB, err := a.db.DB(); err == nil {
			sqlDB.Close()
		}
	}
}

