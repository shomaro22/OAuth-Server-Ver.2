package db

import (
	"context"
	"fmt"
	"os"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// DefaultConnectTimeoutはDB接続のデフォルトタイムアウト（秒）。
const DefaultConnectTimeout = 5

// ConfigはDB接続設定。
type Config struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	SSLMode  string
}

// NewConfigは環境変数からConfigを生成する。
func NewConfig() *Config {
	return &Config{
		Host:     getEnv("DB_HOST", "localhost"),
		Port:     getEnv("DB_PORT", "5432"),
		User:     getEnv("DB_USER", "postgres"),
		Password: getEnv("DB_PASSWORD", "postgres"),
		DBName:   getEnv("DB_NAME", "oauth_server"),
		SSLMode:  getEnv("DB_SSLMODE", "disable"),
	}
}

// DSN（データソース名）はPostgreSQL接続文字列を返す。
func (c *Config) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.DBName, c.SSLMode,
	)
}

// NewDB は GORM の DB 接続を生成する。
// 起動時に Ping で接続確認を行う（DB が死んでいると起動が無限待ちになるのを防ぐ）。
// ※ AutoMigrate は本番で使わない（migration ツールを使用すること）。
func NewDB(cfg *Config) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(cfg.DSN()), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("gorm open: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("get underlying sql.DB: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), DefaultConnectTimeout*time.Second)
	defer cancel()
	if err := sqlDB.PingContext(ctx); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return db, nil
}

func getEnv(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}
