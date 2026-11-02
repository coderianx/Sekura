// Package secret provides authenticated encryption for Sekura secrets using
// AES-GCM. Ciphertexts are hex encoded and include a fresh random nonce.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// Encrypt encrypts plaintext with AES-GCM using key and returns the nonce and
// ciphertext as one lowercase hexadecimal string. Every call uses a fresh
// random nonce.
//
// It returns an error if key is not a valid AES key length or if random nonce
// generation fails.
func Encrypt(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	return hex.EncodeToString(ciphertext), nil
}

// Decrypt decodes an AES-GCM ciphertext produced by [Encrypt] and returns its
// plaintext. The ciphertext must begin with the nonce used during encryption.
//
// It returns an error for malformed hexadecimal input, an invalid AES key, a
// truncated ciphertext, or a failed authentication check.
func Decrypt(encrypted string, key []byte) (string, error) {
	data, err := hex.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()

	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
