package mailer

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"

	"account-manager/internal/config"
)

// Send sends a plain-text email. Returns an error if SMTP is not configured or sending fails.
// Supports three TLS modes via SMTP_TLS env var:
//   - "starttls" (default): connects on port 587, upgrades with STARTTLS
//   - "tls": connects with implicit TLS (port 465 / SMTPS)
//   - "none": plaintext, for local dev only
func Send(cfg *config.Config, to, subject, body string) error {
	if cfg.SMTPHost == "" {
		return fmt.Errorf("SMTP not configured")
	}
	addr := cfg.SMTPHost + ":" + cfg.SMTPPort
	from := cfg.SMTPFrom
	if from == "" {
		from = cfg.SMTPUser
	}

	msg := []byte(strings.Join([]string{
		"From: " + from,
		"To: " + to,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		body,
	}, "\r\n"))

	switch cfg.SMTPTLSMode {
	case "tls":
		return sendImplicitTLS(addr, cfg, from, to, msg)
	case "none":
		return smtp.SendMail(addr, nil, from, []string{to}, msg)
	default: // "starttls"
		return smtp.SendMail(addr, smtpAuth(cfg), from, []string{to}, msg)
	}
}

func smtpAuth(cfg *config.Config) smtp.Auth {
	if cfg.SMTPUser == "" {
		return nil
	}
	return smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPHost)
}

func sendImplicitTLS(addr string, cfg *config.Config, from, to string, msg []byte) error {
	tlsCfg := &tls.Config{ServerName: cfg.SMTPHost} //nolint:gosec // MinVersion inherits Go default (TLS 1.2+)
	conn, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("smtp tls dial: %w", err)
	}
	defer conn.Close()

	host, _, _ := net.SplitHostPort(addr)
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("smtp new client: %w", err)
	}
	defer c.Close()

	if cfg.SMTPUser != "" {
		if err := c.Auth(smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPHost)); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
