// Package core manages TOTP account metadata stored in Sekura's SQLite
// database. Plaintext account secrets are encrypted before persistence;
// retrieval functions expose only encrypted material.
package core

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/coderianx/Sekura/internal/config"
	"github.com/coderianx/Sekura/internal/secret"
	"github.com/coderianx/Sekura/internal/store"
	"github.com/pquerna/otp/totp"
)

// CoreErrNotFound is returned when a requested TOTP account does not exist.
var CoreErrNotFound = errors.New("totp account not found")

// NewTOTPAccount encrypts a TOTP secret with the AES-256 key held in the
// operating system keyring and persists the ciphertext for the supplied issuer
// and account name.
//
// NewTOTPAccount requires [store.DB] to be connected. It returns an error when
// the database is unavailable, the keyring value cannot be loaded or decoded,
// encryption fails, or the account cannot be inserted.
func NewTOTPAccount(
	secretKey string,
	issurer string,
	account_name string,
) error {

	if store.DB == nil {
		return fmt.Errorf("database not connected")
	}

	encryptionKey, err := config.LoadSecretKey()

	if err != nil {
		return fmt.Errorf("load secret key for aes 256 gcm: %w", err)
	}

	cipher, err := secret.Encrypt(secretKey, encryptionKey)

	if err != nil {
		return fmt.Errorf("encrypt secret key error: %w", err)
	}

	_, err = store.DB.Exec(
		`
		INSERT INTO accounts (issuer, account_name, encrypted_secret)
		VALUES (?,?,?)
		`,
		issurer,
		account_name,
		cipher,
	)

	if err != nil {
		return fmt.Errorf("insert database error: %w", err)
	}

	return nil
}

// GetAllTOTPAccounts returns all TOTP account metadata in the database's
// default retrieval order. The encrypted secret is intentionally omitted.
//
// It panics if [store.DB] has not been connected and returns an error if the
// query, row scan, or row iteration fails. With no rows it returns a nil slice.
func GetAllTOTPAccounts() ([]TOTPAccounts, error) {
	rows, err := store.DB.Query(
		`
  		SELECT id, issuer, account_name, created_at
        FROM accounts
		`,
	)

	if err != nil {
		return nil, fmt.Errorf("database query error: %w", err)
	}

	defer rows.Close()

	var accounts []TOTPAccounts

	for rows.Next() {
		var account TOTPAccounts

		err := rows.Scan(
			&account.ID,
			&account.Issuer,
			&account.AccountName,
			&account.CreatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("scan accounts error: %w", err)
		}

		accounts = append(accounts, account)
	}

	err = rows.Err()

	if err != nil {
		return nil, err
	}

	return accounts, nil
}

// GetTOTPAccountByID returns the TOTP account metadata and encrypted secret
// identified by id.
//
// It rejects zero ids, returns an error when no matching account exists, and
// wraps other database failures. It panics if [store.DB] has not been connected.
func GetTOTPAccountByID(id int) (TOTPAccountsWithKey, error) {

	account := TOTPAccountsWithKey{}

	if id == 0 {
		return TOTPAccountsWithKey{}, errors.New("invalid id")
	}

	err := store.DB.QueryRow(
		`
		SELECT id, issuer, account_name, encrypted_secret, created_at
        FROM accounts
        WHERE id = ?
		`,
		id,
	).Scan(
		&account.ID,
		&account.Issuer,
		&account.AccountName,
		&account.EncryptedKey,
		&account.CreatedAt,
	)

	if err != nil {

		if errors.Is(err, sql.ErrNoRows) {
			return TOTPAccountsWithKey{}, CoreErrNotFound
		}

		return TOTPAccountsWithKey{}, fmt.Errorf("fetch totp account err: %w", err)
	}

	return account, nil

}

// GenerateOTPCode decrypts the TOTP secret for the account identified by id and
// returns a current verification code.
//
// It returns [CoreErrNotFound] when no matching account exists and wraps
// database, keyring, decryption, or TOTP generation errors. It panics if
// [store.DB] has not been connected.
func GenerateOTPCode(id int) (string, error) {

	account, err := GetTOTPAccountByID(id)

	if err != nil {
		return "", err
	}

	encryptionKey, err := config.LoadSecretKey()

	if err != nil {
		return "", fmt.Errorf("load secret key from keyring: %w", err)
	}

	key, err := secret.Decrypt(account.EncryptedKey, encryptionKey)

	if err != nil {
		return "", fmt.Errorf("decrypt key error: %w", err)
	}

	code, err := totp.GenerateCode(key, time.Now())

	if err != nil {
		return "", fmt.Errorf("generate otp code error: %w", err)
	}

	return code, nil
}
