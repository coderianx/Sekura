package core

import (
	"path/filepath"
	"testing"

	"github.com/coderianx/Sekura/internal/config"
	"github.com/coderianx/Sekura/internal/store"
	"github.com/zalando/go-keyring"
)

func TestTOTPAccountRoundTrip(t *testing.T) {
	keyring.MockInit()

	if err := config.CreateSecretKey(); err != nil {
		t.Fatalf("config.CreateSecretKey() error = %v", err)
	}

	dbPath := filepath.Join(t.TempDir(), "sekura-test.db")
	if err := store.ConnectDB(dbPath); err != nil {
		t.Fatalf("store.ConnectDB() error = %v", err)
	}

	t.Cleanup(func() {
		if err := store.CloseDB(); err != nil {
			t.Errorf("store.CloseDB() error = %v", err)
		}
	})

	if err := store.CreateTables(); err != nil {
		t.Fatalf("store.CreateTables() error = %v", err)
	}

	const totpSecret = "JBSWY3DPEHPK3PXP"
	if err := NewTOTPAccount(totpSecret, "Sekura", "tester"); err != nil {
		t.Fatalf("NewTOTPAccount() error = %v", err)
	}

	accounts, err := GetAllTOTPAccounts()
	if err != nil {
		t.Fatalf("GetAllTOTPAccounts() error = %v", err)
	}

	if len(accounts) != 1 {
		t.Fatalf("account count = %d, want 1", len(accounts))
	}

	account, err := GetTOTPAccountByID(accounts[0].ID)
	if err != nil {
		t.Fatalf("GetTOTPAccountByID() error = %v", err)
	}

	if account.EncryptedKey == "" || account.EncryptedKey == totpSecret {
		t.Fatal("encrypted key was not stored as ciphertext")
	}

	code, err := GenerateOTPCode(accounts[0].ID)
	if err != nil {
		t.Fatalf("GenerateOTPCode() error = %v", err)
	}

	if len(code) != 6 {
		t.Fatalf("code length = %d, want 6", len(code))
	}

	for _, digit := range code {
		if digit < '0' || digit > '9' {
			t.Fatalf("code = %q, want six decimal digits", code)
		}
	}
}
