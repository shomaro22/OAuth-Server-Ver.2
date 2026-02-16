package database

import (
	"testing"
)

func TestConfig_DSN(t *testing.T) {
	cfg := &Config{
		Host:     "localhost",
		Port:     "5432",
		User:     "postgres",
		Password: "secret",
		DBName:   "oauth_server",
		SSLMode:  "disable",
	}

	dsn := cfg.DSN()
	expected := "postgres://postgres:secret@localhost:5432/oauth_server?sslmode=disable"
	if dsn != expected {
		t.Errorf("DSN() = %s, want %s", dsn, expected)
	}
}

func TestNewConfig(t *testing.T) {
	cfg := NewConfig()
	if cfg.Host == "" {
		t.Error("Host should not be empty")
	}
	if cfg.Port == "" {
		t.Error("Port should not be empty")
	}
	if cfg.DBName == "" {
		t.Error("DBName should not be empty")
	}
}

