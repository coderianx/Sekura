// Package config resolves Sekura's local storage location and manages the
// application's encryption key in the operating system keyring.
package config

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zalando/go-keyring"
)

const aes256KeySize = 32

var (
	// Service is the keyring service name shared by Sekura's credentials.
	Service string = "sekura"

	// SecretKeyUser is the keyring entry name for the AES-256 master key.
	SecretKeyUser string = "aes-256-secret"
)

// SekuraPath is the local data directory assigned by [Init]. It is empty until
// [Init] sets it to the current user's $HOME/.sekura path.
var SekuraPath string

// Init prepares Sekura's local data directory. It resolves the current user's
// home directory, sets [SekuraPath] to $HOME/.sekura, and creates that
// directory with mode 0755 when it does not already exist.
//
// Init returns an error if the home directory cannot be resolved or the
// directory cannot be created.
func Init() error {

	home, err := os.UserHomeDir()

	if err != nil {
		return fmt.Errorf("config: get user home dir error: %w", err)
	}

	SekuraPath = filepath.Join(home, ".sekura")

	err = os.MkdirAll(SekuraPath, 0755)

	if err != nil {
		return fmt.Errorf("config: create .sekura folder error")
	}

	return nil
}

// CreateSecretKey ensures that a valid 32-byte AES-256 master key is stored in
// the operating system keyring under [Service] and [SecretKeyUser].
//
// If a key already exists, CreateSecretKey validates it and leaves it
// unchanged. Otherwise, it generates a cryptographically random key, encodes it
// with Base64, and stores it. An invalid existing value is reported instead of
// being overwritten so encrypted data cannot be silently orphaned.
//
// CreateSecretKey returns an error if keyring access fails, an existing value is
// invalid, random generation fails, or the keyring rejects the write.
func CreateSecretKey() error {
	if _, err := LoadSecretKey(); err == nil {
		return nil
	} else if !errors.Is(err, keyring.ErrNotFound) {
		return err
	}

	key := make([]byte, aes256KeySize)

	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("config: generate secret key: %w", err)
	}

	encodedKey := base64.StdEncoding.EncodeToString(key)

	if err := keyring.Set(Service, SecretKeyUser, encodedKey); err != nil {
		return fmt.Errorf("config: store secret key: %w", err)
	}

	return nil
}

// LoadSecretKey retrieves the AES-256 master key from the operating system
// keyring and decodes its Base64 representation. It returns a 32-byte key.
//
// A missing key produces an error that wraps [keyring.ErrNotFound]. LoadSecretKey
// also returns an error when the stored value is not valid Base64 or does not
// decode to exactly 32 bytes.
func LoadSecretKey() ([]byte, error) {
	encodedKey, err := keyring.Get(Service, SecretKeyUser)
	if err != nil {
		return nil, fmt.Errorf("config: get secret key from keyring: %w", err)
	}

	key, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return nil, fmt.Errorf("config: decode secret key: %w", err)
	}

	if len(key) != aes256KeySize {
		return nil, fmt.Errorf(
			"config: invalid secret key length %d, want %d",
			len(key),
			aes256KeySize,
		)
	}

	return key, nil
}
