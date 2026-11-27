package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/joho/godotenv"

	"account-manager/internal/config"
	"account-manager/internal/db"
	"account-manager/internal/handler"
	"account-manager/internal/setup"
)

func main() {
	// Load .env if present (ignored in production where vars are set directly).
	_ = godotenv.Load()

	cfg := config.Load()

	// Open DB (runs migrations).
	sqlDB, err := db.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}

	// Run idempotent setup: key gen + OAuth client seeding.
	kp, err := setup.EnsureInitialized(cfg.DataDir,
		setup.ClientURIs{RedirectURI: cfg.GamebacklogRedirect, BackchannelURI: cfg.GamebacklogBackchannelURI},
		setup.ClientURIs{RedirectURI: cfg.ServiceManagerRedirect, BackchannelURI: cfg.ServiceManagerBackchannelURI},
		setup.ClientURIs{RedirectURI: cfg.ChoreChartRedirect, BackchannelURI: cfg.ChoreChartBackchannelURI},
		setup.ClientURIs{RedirectURI: cfg.ClaudePortalRedirect},
		setup.ClientURIs{RedirectURI: cfg.PiHealthRedirect, BackchannelURI: cfg.PiHealthBackchannelURI},
		sqlDB,
	)
	if err != nil {
		log.Fatalf("Setup failed: %v", err)
	}

	app := &handler.App{DB: sqlDB, Keys: kp, Cfg: cfg}

	r := newRouter(app, cfg)

	addr := fmt.Sprintf(":%s", cfg.Port)
	log.Printf("account-manager listening on %s", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
