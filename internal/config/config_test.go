package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/zalando/go-keyring"
)

func TestCreateSecretKeyCreatesAndPreservesKey(t *testing.T) {
	keyring.MockInit()

	if err := CreateSecretKey(); err != nil {
		t.Fatalf("CreateSecretKey() error = %v", err)
	}

	first, err := keyring.Get(Service, SecretKeyUser)
	if err != nil {
		t.Fatalf("keyring.Get() error = %v", err)
	}

	key, err := LoadSecretKey()
	if err != nil {
		t.Fatalf("LoadSecretKey() error = %v", err)
	}

	if len(key) != aes256KeySize {
		t.Fatalf("key length = %d, want %d", len(key), aes256KeySize)
	}

	if bytes.Equal(key, make([]byte, aes256KeySize)) {
		t.Fatal("generated key must not be all zero")
	}

	if err := CreateSecretKey(); err != nil {
		t.Fatalf("second CreateSecretKey() error = %v", err)
	}

	second, err := keyring.Get(Service, SecretKeyUser)
	if err != nil {
		t.Fatalf("second keyring.Get() error = %v", err)
	}

	if first != second {
		t.Fatal("CreateSecretKey() replaced an existing key")
	}
}

func TestLoadSecretKeyDecodesStoredKey(t *testing.T) {
	keyring.MockInit()

	want := bytes.Repeat([]byte{0x5a}, aes256KeySize)
	encoded := base64.StdEncoding.EncodeToString(want)

	if err := keyring.Set(Service, SecretKeyUser, encoded); err != nil {
		t.Fatalf("keyring.Set() error = %v", err)
	}

	got, err := LoadSecretKey()
	if err != nil {
		t.Fatalf("LoadSecretKey() error = %v", err)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("LoadSecretKey() = %x, want %x", got, want)
	}
}

func TestLoadSecretKeyRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{
			name:  "invalid base64",
			value: "not-valid-base64!",
		},
		{
			name:  "wrong decoded length",
			value: base64.StdEncoding.EncodeToString([]byte("too-short")),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keyring.MockInit()

			if err := keyring.Set(Service, SecretKeyUser, tc.value); err != nil {
				t.Fatalf("keyring.Set() error = %v", err)
			}

			if _, err := LoadSecretKey(); err == nil {
				t.Fatal("LoadSecretKey() error = nil, want an error")
			}
		})
	}
}

func TestCreateSecretKeyRejectsInvalidExistingKey(t *testing.T) {
	keyring.MockInit()

	const invalid = "not-valid-base64!"
	if err := keyring.Set(Service, SecretKeyUser, invalid); err != nil {
		t.Fatalf("keyring.Set() error = %v", err)
	}

	if err := CreateSecretKey(); err == nil {
		t.Fatal("CreateSecretKey() error = nil, want an error")
	}

	got, err := keyring.Get(Service, SecretKeyUser)
	if err != nil {
		t.Fatalf("keyring.Get() error = %v", err)
	}

	if got != invalid {
		t.Fatal("CreateSecretKey() overwrote an invalid existing key")
	}
}

func TestLoadSecretKeyReturnsNotFound(t *testing.T) {
	keyring.MockInit()

	if _, err := LoadSecretKey(); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatalf("LoadSecretKey() error = %v, want keyring.ErrNotFound", err)
	}
}
