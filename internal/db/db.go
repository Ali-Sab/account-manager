package db

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

func Open(dbPath string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec("PRAGMA journal_mode = WAL"); err != nil {
		return nil, err
	}
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return nil, err
	}
	// Without this, a writer that can't immediately acquire the lock (e.g. two
	// transactions racing on BEGIN IMMEDIATE) fails instantly with "database
	// is locked" instead of waiting briefly for the other to commit.
	if _, err := db.Exec("PRAGMA busy_timeout = 5000"); err != nil {
		return nil, err
	}
	if err := migrate(db); err != nil {
		return nil, err
	}
	return db, nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS credentials (
			id              INTEGER PRIMARY KEY CHECK (id = 1),
			username        TEXT NOT NULL,
			hash            TEXT NOT NULL,
			salt            TEXT NOT NULL,
			totp_secret     TEXT NOT NULL,
			recovery_codes  TEXT
		);

		CREATE TABLE IF NOT EXISTS users (
			id              INTEGER PRIMARY KEY AUTOINCREMENT,
			username        TEXT NOT NULL UNIQUE,
			hash            TEXT NOT NULL,
			salt            TEXT NOT NULL,
			totp_secret     TEXT NOT NULL DEFAULT '',
			recovery_codes  TEXT,
			is_admin        INTEGER NOT NULL DEFAULT 0,
			created_at      INTEGER NOT NULL DEFAULT 0
		);

		CREATE TABLE IF NOT EXISTS refresh_tokens (
			token      TEXT PRIMARY KEY,
			expires_at INTEGER NOT NULL
		);

		CREATE TABLE IF NOT EXISTS pending_setup (
			id         INTEGER PRIMARY KEY CHECK (id = 1),
			secret     TEXT NOT NULL,
			created_at INTEGER NOT NULL
		);

		CREATE TABLE IF NOT EXISTS passkey_credentials (
			credential_id TEXT PRIMARY KEY,
			public_key    TEXT NOT NULL,
			counter       INTEGER NOT NULL DEFAULT 0,
			device_name   TEXT,
			created_at    TEXT NOT NULL
		);

		CREATE TABLE IF NOT EXISTS webauthn_challenges (
			id         INTEGER PRIMARY KEY CHECK (id = 1),
			challenge  TEXT NOT NULL,
			created_at INTEGER NOT NULL
		);

		CREATE TABLE IF NOT EXISTS webauthn_sessions (
			purpose    TEXT PRIMARY KEY,
			challenge  TEXT NOT NULL,
			created_at INTEGER NOT NULL
		);

		CREATE TABLE IF NOT EXISTS setup_state (
			id          INTEGER PRIMARY KEY CHECK (id = 1),
			username    TEXT,
			hash        TEXT,
			salt        TEXT,
			challenge   TEXT,
			created_at  INTEGER NOT NULL
		);

		CREATE TABLE IF NOT EXISTS oauth_clients (
			client_id          TEXT PRIMARY KEY,
			client_secret_hash TEXT NOT NULL,
			redirect_uris      TEXT NOT NULL,
			name               TEXT,
			audience           TEXT NOT NULL DEFAULT 'mcp'
		);

		CREATE TABLE IF NOT EXISTS oauth_auth_codes (
			code                   TEXT PRIMARY KEY,
			client_id              TEXT NOT NULL,
			redirect_uri           TEXT NOT NULL,
			code_challenge         TEXT,
			code_challenge_method  TEXT,
			expires_at             INTEGER NOT NULL,
			used                   INTEGER NOT NULL DEFAULT 0
		);

		CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
			token_hash  TEXT PRIMARY KEY,
			client_id   TEXT NOT NULL,
			expires_at  INTEGER NOT NULL
		);

		CREATE TABLE IF NOT EXISTS pending_invites (
			token       TEXT PRIMARY KEY,
			invited_by  TEXT NOT NULL,
			totp_secret TEXT,
			created_at  INTEGER NOT NULL
		);

		CREATE TABLE IF NOT EXISTS password_reset_tokens (
			token      TEXT PRIMARY KEY,
			username   TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL
		);

		CREATE TABLE IF NOT EXISTS email_verification_tokens (
			token      TEXT PRIMARY KEY,
			username   TEXT NOT NULL,
			email      TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL
		);
	`)
	if err != nil {
		return err
	}

	// Additive column migrations for existing DBs.
	for _, stmt := range []string{
		`ALTER TABLE passkey_credentials ADD COLUMN backup_eligible INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE passkey_credentials ADD COLUMN backup_state    INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE passkey_credentials ADD COLUMN username        TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE refresh_tokens      ADD COLUMN username        TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE oauth_auth_codes    ADD COLUMN username        TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE oauth_refresh_tokens ADD COLUMN username       TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE users               ADD COLUMN email           TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE oauth_clients       ADD COLUMN client_secret           TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE oauth_clients       ADD COLUMN backchannel_logout_uri  TEXT NOT NULL DEFAULT ''`,
	} {
		if _, err := db.Exec(stmt); err != nil && !isAlreadyExistsErr(err) {
			return err
		}
	}

	// Migrate single-user credentials row → users table (upgrade path).
	if _, err := db.Exec(`
		INSERT OR IGNORE INTO users (username, hash, salt, totp_secret, recovery_codes, is_admin, created_at)
		SELECT username, hash, salt, totp_secret, recovery_codes, 1,
		       CAST(strftime('%s','now') AS INTEGER) * 1000
		FROM credentials
		WHERE NOT EXISTS (SELECT 1 FROM users)
	`); err != nil {
		return err
	}

	// Back-fill username on existing passkey_credentials to the migrated user.
	if _, err := db.Exec(`
		UPDATE passkey_credentials
		SET username = COALESCE((SELECT username FROM credentials LIMIT 1), '')
		WHERE username = ''
	`); err != nil {
		return err
	}

	// Back-fill username on existing session tokens.
	if _, err := db.Exec(`
		UPDATE refresh_tokens
		SET username = COALESCE((SELECT username FROM credentials LIMIT 1), '')
		WHERE username = ''
	`); err != nil {
		return err
	}
	if _, err := db.Exec(`
		UPDATE oauth_auth_codes
		SET username = COALESCE((SELECT username FROM credentials LIMIT 1), '')
		WHERE username = ''
	`); err != nil {
		return err
	}
	if _, err := db.Exec(`
		UPDATE oauth_refresh_tokens
		SET username = COALESCE((SELECT username FROM credentials LIMIT 1), '')
		WHERE username = ''
	`); err != nil {
		return err
	}

	// Existing passkeys assumed backup-eligible (iCloud Keychain / platform passkeys).
	if _, err := db.Exec(`UPDATE passkey_credentials SET backup_eligible = 1 WHERE backup_eligible = 0`); err != nil {
		return err
	}

	return nil
}

func isAlreadyExistsErr(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "duplicate column") || strings.Contains(err.Error(), "already exists"))
}
