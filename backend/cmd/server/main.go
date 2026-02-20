package main

import (
	"log"

	"github.com/joho/godotenv"
	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/app"
)

func main() {
	// backend/ から起動時は .env を読み込む（上書きしない）
	_ = godotenv.Load()
	application, err := app.New()
	if err != nil {
		log.Fatalf("Failed to initialize app: %v", err)
	}
	defer application.Close()

	if err := application.Run(); err != nil {
		log.Fatalf("App error: %v", err)
	}
}
