# Sekura

Sekura is a Go-based application intended to store TOTP account information
locally in encrypted form. Account metadata is stored in SQLite, TOTP secrets
are encrypted with AES-GCM, and the master key is stored in the operating
system keyring.

> [!IMPORTANT]
> Sekura is in early development. It does not yet provide a user-facing CLI or
> TUI, an account management workflow, or the security hardening required for
> production use. The current application only prepares the local data directory
> and master key. Do not use it with real accounts.

## Features

- AES-GCM encryption for TOTP account secrets
- Cryptographically secure random nonce generation for every encryption
- Master key management through the operating system keyring
- CGO-free data storage using a pure Go SQLite driver
- WAL, foreign key, busy timeout, and secure delete settings
- `0600` permissions for database files
- APIs for creating, listing, and querying accounts and generating TOTP codes

## Project Status

This repository is currently an application skeleton. The following features
are not yet available:

- A user-facing command-line or terminal interface
- Database connection and schema setup during application startup
- Account updates, deletion, import/export, and backup
- Schema versioning and database migrations
- Comprehensive unit and integration tests

## Security Model

- Each TOTP secret is encrypted with AES-GCM using a 32-byte master key stored
  in the operating system keyring.
- Every encryption operation generates a new random nonce. The nonce is
  prepended to the ciphertext, and the result is stored as a hexadecimal string.
- SQLite connections are configured with WAL, foreign keys, a five-second busy
  timeout, and secure delete.
- On regular filesystem paths, the database file is created with `0600`
  permissions.

> [!NOTE]
> On first run, the master key is generated with `crypto/rand`, Base64 encoded,
> and written to the keyring. It is not replaced on subsequent runs. If records
> were previously encrypted with a different key, a controlled migration is
> required; if the old key is lost, those records cannot be decrypted.

## Requirements

- Go 1.27.1 or later
- An operating system with keyring support
  (macOS Keychain, Windows Credential Manager, or Linux Secret Service)
- No C compiler required

## Installation and Build

```bash
git clone https://github.com/coderianx/Sekura.git
cd Sekura
go mod download
go build -o sekura .
./sekura
```

> [!NOTE]
> The `main` package produces an executable binary. Alternatively, you can run
> `go run .`. The current startup flow only prepares the `~/.sekura` directory
> and master key; it does not open the database or start an interactive UI.

## Project Structure

```text
.
├── main.go                  # Application startup flow
├── internal/
│   ├── config/              # Local directory and keyring configuration
│   ├── core/                # TOTP account operations and data model
│   ├── secret/              # AES-GCM encryption and decryption
│   └── store/               # SQLite connection and schema management
├── go.mod
├── go.sum
├── LICENSE
└── README.md
```

## API Overview

| Package | Declaration | Description |
| --- | --- | --- |
| `config` | `Init` | Creates the `~/.sekura` directory and configures its path. |
| `config` | `CreateSecretKey` | Creates a master key if absent and preserves an existing one. |
| `config` | `LoadSecretKey` | Decodes the Base64 key and verifies that it is 32 bytes. |
| `store` | `ConnectDB` | Opens and configures a SQLite connection. |
| `store` | `CreateTables` | Creates the required database table. |
| `store` | `CloseDB` | Closes the active SQLite connection. |
| `core` | `NewTOTPAccount` | Encrypts a TOTP secret and persists the account. |
| `core` | `GetAllTOTPAccounts` | Lists account metadata. |
| `core` | `GetTOTPAccountByID` | Retrieves an account and its encrypted secret. |
| `core` | `GenerateOTPCode` | Generates a current TOTP code for an account. |
| `secret` | `Encrypt` | Encrypts text with AES-GCM. |
| `secret` | `Decrypt` | Decrypts AES-GCM ciphertext. |

## Data Model

The `accounts` table contains the following fields:

| Field | Type | Description |
| --- | --- | --- |
| `id` | `INTEGER` | Auto-incrementing primary key |
| `issuer` | `TEXT` | Service or organization that issued the account |
| `account_name` | `TEXT` | User account name |
| `encrypted_secret` | `TEXT` | Hex-encoded AES-GCM ciphertext of the TOTP secret |
| `created_at` | `DATETIME` | Record creation timestamp |

## Local Data

- Local data directory: `~/.sekura`
- Keyring service name: `sekura`
- Keyring entry name: `aes-256-secret`
- Recommended database path: `~/.sekura/sekura.db`

## Development

Run the formatting, build, and test checks before submitting changes:

```bash
gofmt -l .
go build ./...
go test ./...
```

The `gofmt -l .` command must produce no output.

## License

This project is licensed under the [MIT License](LICENSE).
