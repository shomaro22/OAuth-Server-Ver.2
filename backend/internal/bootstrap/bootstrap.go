package bootstrap

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/shomaro22/OAuth-Server-Ver.2/backend/migrations"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

const (
	seedUserID   = "00000000-0000-0000-0000-000000000001"
	seedClientID = "11111111-1111-1111-1111-111111111111"
)

var migrationOrder = []string{
	"000_initial.sql",
	"001_add_session_id.sql",
	"002_client_secret_hash.sql",
	"003_add_allowed_scopes.sql",
	"004_add_nonce_to_authorization_codes.sql",
	"005_add_password_hash_to_users.sql",
}

// RunOnStart は AUTO_MIGRATE_ON_START / AUTO_SEED_ON_START が有効なとき DB を初期化する。
func RunOnStart(db *gorm.DB) error {
	if isTruthy(os.Getenv("AUTO_MIGRATE_ON_START")) {
		if err := runMigrations(db); err != nil {
			return fmt.Errorf("auto migrate: %w", err)
		}
	}
	if isTruthy(os.Getenv("AUTO_SEED_ON_START")) {
		if err := runSeed(db); err != nil {
			return fmt.Errorf("auto seed: %w", err)
		}
	}
	return nil
}

func runMigrations(db *gorm.DB) error {
	if err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			filename VARCHAR(255) PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`).Error; err != nil {
		return fmt.Errorf("schema_migrations table: %w", err)
	}

	for _, name := range migrationOrder {
		var count int64
		if err := db.Raw("SELECT COUNT(*) FROM schema_migrations WHERE filename = ?", name).Scan(&count).Error; err != nil {
			return err
		}
		if count > 0 {
			continue
		}

		body, err := migrations.Files.ReadFile(name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}

		if err := db.Exec(string(body)).Error; err != nil {
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
		if err := db.Exec("INSERT INTO schema_migrations (filename) VALUES (?)", name).Error; err != nil {
			return fmt.Errorf("record migration %s: %w", name, err)
		}
		log.Printf("Applied migration: %s", name)
	}

	log.Println("Auto migration complete")
	return nil
}

func runSeed(db *gorm.DB) error {
	password := getenv("AUTO_SEED_PASSWORD", "password123")
	redirectURI := seedRedirectURI()

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	err = db.Exec(`
		INSERT INTO users (id, email, username, password_hash, email_verified, status, created_at, updated_at)
		VALUES (
			?::uuid,
			'test@example.com',
			'testuser',
			?,
			false,
			'active',
			NOW(),
			NOW()
		)
		ON CONFLICT (id) DO UPDATE SET
			password_hash = EXCLUDED.password_hash,
			updated_at = NOW()`,
		seedUserID, string(hash),
	).Error
	if err != nil {
		return fmt.Errorf("seed user: %w", err)
	}

	err = db.Exec(`
		INSERT INTO clients (id, client_secret_hash, redirect_uris, allowed_scopes)
		VALUES (
			?::uuid,
			'',
			?,
			'openid profile'
		)
		ON CONFLICT (id) DO UPDATE SET
			redirect_uris = EXCLUDED.redirect_uris,
			allowed_scopes = EXCLUDED.allowed_scopes`,
		seedClientID, redirectURI,
	).Error
	if err != nil {
		return fmt.Errorf("seed client: %w", err)
	}

	log.Printf("Auto seed complete (user=testuser, client_id=%s, redirect_uri=%s)", seedClientID, redirectURI)
	return nil
}

func seedRedirectURI() string {
	if v := os.Getenv("AUTO_SEED_REDIRECT_URI"); v != "" {
		return v
	}
	if cors := os.Getenv("CORS_ORIGIN"); cors != "" {
		return strings.TrimRight(cors, "/") + "/callback"
	}
	return "http://localhost:5173/callback"
}

func isTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func getenv(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}
