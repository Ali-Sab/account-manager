package config

import (
	"os"
	"path/filepath"
	"strconv"
)

type Config struct {
	Port                  string
	DataDir               string
	DBPath                string
	CsrfSecret            string
	JWTIssuer             string
	WebAuthnRPID          string
	WebAuthnRPName        string
	IsProd                bool
	GamebacklogRedirect              string
	ServiceManagerRedirect          string
	ChoreChartRedirect              string
	GamebacklogBackchannelURI       string
	ServiceManagerBackchannelURI    string
	ChoreChartBackchannelURI        string
	SMTPHost              string
	SMTPPort              string
	SMTPUser              string
	SMTPPass              string
	SMTPFrom              string
	// SMTPTLSMode controls transport security: "starttls" (default, port 587),
	// "tls" (implicit TLS, port 465), or "none" (plaintext, dev only).
	SMTPTLSMode           string
	// RateLimitMax is the max requests per IP per 15-minute window on auth/setup routes.
	RateLimitMax          int
}

func Load() *Config {
	dataDir := getenv("DATA_DIR", "./data")
	dbPath := getenv("DB_PATH", filepath.Join(dataDir, "account-manager.db"))
	return &Config{
		Port:               getenv("PORT", "3001"),
		DataDir:            dataDir,
		DBPath:             dbPath,
		CsrfSecret:         getenv("CSRF_SECRET", "change-me-in-production"),
		JWTIssuer:          getenv("JWT_ISSUER", "http://localhost:3001"),
		WebAuthnRPID:       getenv("WEBAUTHN_RP_ID", "localhost"),
		WebAuthnRPName:     getenv("WEBAUTHN_RP_NAME", "Account Manager"),
		IsProd:             os.Getenv("NODE_ENV") == "production",
		GamebacklogRedirect:           getenv("GAMEBACKLOG_REDIRECT_URI", "http://localhost:3010/auth/callback"),
		ServiceManagerRedirect:        getenv("SERVICE_MANAGER_REDIRECT_URI", "http://localhost:8082/oauth/callback"),
		ChoreChartRedirect:            getenv("CHORE_CHART_REDIRECT_URI", "http://localhost:8080/oauth/callback"),
		GamebacklogBackchannelURI:     getenv("GAMEBACKLOG_BACKCHANNEL_URI", ""),
		ServiceManagerBackchannelURI:  getenv("SERVICE_MANAGER_BACKCHANNEL_URI", ""),
		ChoreChartBackchannelURI:      getenv("CHORE_CHART_BACKCHANNEL_URI", ""),
		SMTPHost:               getenv("SMTP_HOST", ""),
		SMTPPort:               getenv("SMTP_PORT", "587"),
		SMTPUser:               getenv("SMTP_USER", ""),
		SMTPPass:               getenv("SMTP_PASS", ""),
		SMTPFrom:               getenv("SMTP_FROM", ""),
		SMTPTLSMode:            getenv("SMTP_TLS", "starttls"),
		RateLimitMax:           getenvInt("RATE_LIMIT_MAX", 20),
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}
