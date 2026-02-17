package main

import (
	"log"

	"github.com/shomaro22/OAuth-Server-Ver.2/backend/internal/app"
)

func main() {
	application, err := app.New()
	if err != nil {
		log.Fatalf("Failed to initialize app: %v", err)
	}
	defer application.Close()

	if err := application.Run(); err != nil {
		log.Fatalf("App error: %v", err)
	}
}
