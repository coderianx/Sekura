// Package store owns Sekura's SQLite connection lifecycle and schema. It
// configures connections for concurrency, integrity, and secure deletion, and
// exposes the active handle through [DB].
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"

	_ "modernc.org/sqlite"
)

// DB is the process-wide SQLite handle installed by [ConnectDB] and cleared by
// [CloseDB]. It is nil while no connection is active.
//
// The handle is safe for concurrent database operations, but callers must
// synchronize calls to [ConnectDB] and [CloseDB] with other access to DB.
var DB *sql.DB

// ConnectDB opens an SQLite database at dbPath, applies Sekura's connection
// pragmas, verifies that the database responds, and installs the handle as
// [DB].
//
// For regular filesystem paths, ConnectDB creates the database file when
// needed and enforces mode 0600. Paths beginning with ":memory:" or "file:" are
// passed directly to the SQLite driver without file preparation.
//
// The connection enables WAL journaling, foreign-key enforcement, a five-second
// busy timeout, and secure deletion. If any step fails, ConnectDB closes the
// candidate handle and leaves [DB] unchanged.
func ConnectDB(dbPath string) error {
	if !strings.HasPrefix(dbPath, ":memory:") && !strings.HasPrefix(dbPath, "file:") {
		file, err := os.OpenFile(dbPath, os.O_CREATE|os.O_RDWR, 0600)

		if err != nil {
			return fmt.Errorf("create database file: %w", err)
		}

		file.Close()

		if err := os.Chmod(dbPath, 0600); err != nil {
			return fmt.Errorf("set database permissions: %w", err)
		}
	}

	db, err := sql.Open("sqlite", dbPath)

	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}

	// Enable WAL mode and foreign keys for better concurrency and integrity.
	// secure_delete overwrites deleted content so stale ciphertext does not
	// linger in free pages.
	pragmas := []string{
		"PRAGMA journal_mode = WAL;",
		"PRAGMA foreign_keys = ON;",
		"PRAGMA busy_timeout = 5000;",
		"PRAGMA secure_delete = ON;",
	}

	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return fmt.Errorf("exec pragma %q: %w", pragma, err)
		}
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return fmt.Errorf("ping database: %w", err)
	}

	DB = db

	return nil
}

// CloseDB closes the active SQLite handle and clears [DB]. It returns nil when
// no handle is active and leaves [DB] set if closing fails.
func CloseDB() error {
	if DB == nil {
		return nil
	}

	if err := DB.Close(); err != nil {
		return fmt.Errorf("close database: %w", err)
	}

	DB = nil

	return nil
}

// CreateTables creates the accounts table and its schema when they do not
// already exist. Existing tables and rows are left unchanged.
//
// It returns an error when [DB] is nil or the schema cannot be applied.
func CreateTables() error {
	if DB == nil {
		return errors.New("database not connected")
	}

	const schema = `
CREATE TABLE IF NOT EXISTS accounts (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	issuer TEXT NOT NULL,
	account_name TEXT NOT NULL,
	encrypted_secret TEXT NOT NULL,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`

	if _, err := DB.Exec(schema); err != nil {
		return fmt.Errorf("create tables: %w", err)
	}

	return nil
}
