package core

import "time"

// TOTPAccounts holds the metadata for one persisted TOTP account. It does not
// contain the account's encrypted secret.
type TOTPAccounts struct {
	// ID is the database-assigned primary key of the account.
	ID int

	// Issuer identifies the service or organization that issued the account.
	Issuer string

	// AccountName identifies the user within the issuer's namespace.
	AccountName string

	// CreatedAt is the database timestamp recorded when the account was
	// inserted.
	CreatedAt time.Time
}

// TOTPAccountsWithKey holds the metadata for one persisted TOTP account,
// including the encrypted secret required to generate verification codes.
type TOTPAccountsWithKey struct {
	// ID is the database-assigned primary key of the account.
	ID int

	// Issuer identifies the service or organization that issued the account.
	Issuer string

	// AccountName identifies the user within the issuer's namespace.
	AccountName string

	// EncryptedKey is the hex-encoded AES-GCM ciphertext of the TOTP secret.
	EncryptedKey string

	// CreatedAt is the database timestamp recorded when the account was
	// inserted.
	CreatedAt time.Time
}
