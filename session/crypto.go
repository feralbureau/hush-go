// Package session implements Hush session key exchange,
// authentication, and session lifecycle management.
package session

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

const (
	KeySize   = 32
	NonceSize = 12
	TagSize   = 16
	PubKeySize = 32
)

// GenerateKeyPair creates a new X25519 key pair for session key exchange.
func GenerateKeyPair() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// SharedSecret computes the ECDH shared secret from a private key and a public key.
func SharedSecret(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) ([]byte, error) {
	return priv.ECDH(pub)
}

// DeriveSessionKey derives a 256-bit AES key from the ECDH shared secret
// and the pre-shared API key secret (PSK) using HKDF-SHA256.
func DeriveSessionKey(sharedSecret, apiKeySecret []byte) ([]byte, error) {
	key, err := hkdf.Key(sha256.New, apiKeySecret, sharedSecret, "hush-v1-key", KeySize)
	if err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return key, nil
}

// Encrypt encrypts plaintext with AES-256-GCM using a random nonce.
// Returns nonce || ciphertext (ciphertext includes the auth tag).
func Encrypt(key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, NonceSize+len(ciphertext))
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

// Decrypt decrypts data produced by Encrypt.
func Decrypt(key []byte, data []byte) ([]byte, error) {
	if len(data) < NonceSize+TagSize {
		return nil, fmt.Errorf("session: ciphertext too short (%d bytes)", len(data))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	nonce := data[:NonceSize]
	ciphertext := data[NonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("gcm decrypt: %w", err)
	}
	return plaintext, nil
}

// RandomBytes generates n cryptographically random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("rand: %w", err)
	}
	return b, nil
}
