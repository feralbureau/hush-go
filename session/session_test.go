package session

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestGenerateKeyPair(t *testing.T) {
	priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if priv == nil {
		t.Fatal("expected non-nil private key")
	}
	if len(priv.PublicKey().Bytes()) != PubKeySize {
		t.Fatalf("expected %d byte pubkey, got %d", PubKeySize, len(priv.PublicKey().Bytes()))
	}
}

func TestSharedSecret(t *testing.T) {
	alice, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	bob, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	aliceShared, err := SharedSecret(alice, bob.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	bobShared, err := SharedSecret(bob, alice.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(aliceShared, bobShared) {
		t.Fatal("shared secrets don't match")
	}
}

func TestDeriveSessionKey(t *testing.T) {
	priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey()
	shared, err := SharedSecret(priv, pub)
	if err != nil {
		t.Fatal(err)
	}

	psk := []byte("test-api-key-secret-32-bytes")
	key1, err := DeriveSessionKey(shared, psk)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := DeriveSessionKey(shared, psk)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(key1, key2) {
		t.Fatal("derived keys must be deterministic")
	}
	if len(key1) != KeySize {
		t.Fatalf("expected %d byte key, got %d", KeySize, len(key1))
	}

	key3, _ := DeriveSessionKey(shared, []byte("different-psk"))
	if bytes.Equal(key1, key3) {
		t.Fatal("different PSK must produce different key")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("hello hush protocol")
	encrypted, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	decrypted, err := Decrypt(key, encrypted)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("decrypted doesn't match plaintext")
	}
}

func TestEncryptWrongKey(t *testing.T) {
	key1 := make([]byte, KeySize)
	key2 := make([]byte, KeySize)
	key2[0] = 1

	plaintext := []byte("test")
	encrypted, err := Encrypt(key1, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Decrypt(key2, encrypted)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestEncryptTooShort(t *testing.T) {
	key := make([]byte, KeySize)
	_, err := Decrypt(key, []byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for too-short ciphertext")
	}
}

func TestSessionConfigDefaults(t *testing.T) {
	store := NewSessionStore(SessionConfig{})
	cfg := store.Config()
	if cfg.IdleTimeout != DefaultIdleTimeout {
		t.Fatalf("expected default idle %v, got %v", DefaultIdleTimeout, cfg.IdleTimeout)
	}
	if cfg.MaxLifetime != DefaultMaxLifetime {
		t.Fatalf("expected default lifetime %v, got %v", DefaultMaxLifetime, cfg.MaxLifetime)
	}
	if cfg.GCInterval != DefaultGCInterval {
		t.Fatalf("expected default gc %v, got %v", DefaultGCInterval, cfg.GCInterval)
	}
}

func TestSessionConfigCustom(t *testing.T) {
	cfg := SessionConfig{
		IdleTimeout: 1 * time.Minute,
		MaxLifetime: 1 * time.Hour,
		GCInterval:  5 * time.Second,
	}
	if cfg.IdleTimeout != 1*time.Minute {
		t.Fatal("custom idle timeout not used")
	}
	if cfg.MaxLifetime != 1*time.Hour {
		t.Fatal("custom max lifetime not used")
	}
	if cfg.GCInterval != 5*time.Second {
		t.Fatal("custom gc interval not used")
	}
}

func TestSessionLifecycle(t *testing.T) {
	cfg := SessionConfig{
		IdleTimeout: 50 * time.Millisecond,
		MaxLifetime: 1 * time.Hour,
	}
	store := NewSessionStore(cfg)
	key := make([]byte, KeySize)
	sess := NewSession(1, "test-key", key)
	store.Set(sess)

	if store.IsExpired(sess) {
		t.Fatal("new session should not be expired")
	}

	t.Log("waiting for idle timeout...")
	time.Sleep(100 * time.Millisecond)

	if !store.IsIdleDead(sess) {
		t.Fatal("session should be idle-dead after timeout")
	}
}

func TestSessionStore(t *testing.T) {
	store := NewSessionStore(SessionConfig{})
	key := make([]byte, KeySize)
	sess := NewSession(1, "key1", key)
	store.Set(sess)

	_, ok := store.Get(1)
	if !ok {
		t.Fatal("expected to find session")
	}

	store.Delete(1)
	_, ok = store.Get(1)
	if ok {
		t.Fatal("expected session to be deleted")
	}
}

func TestGenerateAPIKey(t *testing.T) {
	key, err := GenerateAPIKey()
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	if len(key.ID) == 0 {
		t.Fatal("expected non-empty key ID")
	}
	if len(key.Secret) != 32 {
		t.Fatalf("expected 32-byte secret, got %d", len(key.Secret))
	}
}

func TestMapKeyStore(t *testing.T) {
	ks := MapKeyStore{"test": []byte("secret123")}
	if string(ks.Get("test")) != "secret123" {
		t.Fatal("MapKeyStore.Get failed")
	}
	if ks.Get("nonexistent") != nil {
		t.Fatal("expected nil for nonexistent key")
	}
}

func TestConcurrentTouch(t *testing.T) {
	cfg := SessionConfig{IdleTimeout: 1 * time.Second}
	store := NewSessionStore(cfg)
	key := make([]byte, KeySize)
	sess := NewSession(1, "test", key)
	store.Set(sess)

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			sess.Touch()
			done <- true
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}
	if store.IsIdleDead(sess) {
		t.Fatal("session should not be idle-dead after Touches")
	}
}

func TestSessionStoreSetGetDelete(t *testing.T) {
	store := NewSessionStore(SessionConfig{})

	sess1 := NewSession(1, "k1", make([]byte, KeySize))
	sess2 := NewSession(2, "k2", make([]byte, KeySize))

	store.Set(sess1)
	store.Set(sess2)

	got1, ok1 := store.Get(1)
	got2, ok2 := store.Get(2)

	if !ok1 || got1 == nil || got1.ID != 1 {
		t.Fatal("session 1 should exist")
	}
	if !ok2 || got2 == nil || got2.ID != 2 {
		t.Fatal("session 2 should exist")
	}

	_, ok3 := store.Get(999)
	if ok3 {
		t.Fatal("session 999 should not exist")
	}

	store.Delete(999)

	store.Delete(1)
	_, ok1 = store.Get(1)
	if ok1 {
		t.Fatal("session 1 should be deleted")
	}
	_, ok2 = store.Get(2)
	if !ok2 {
		t.Fatal("session 2 should still exist")
	}
}

func TestSessionStoreGCConcurrent(t *testing.T) {
	store := NewSessionStore(SessionConfig{MaxLifetime: 1 * time.Hour})

	for i := 0; i < 100; i++ {
		store.Set(NewSession(uint64(i), fmt.Sprintf("k%d", i), make([]byte, KeySize)))
	}

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			store.GC()
		}()
	}
	wg.Wait()

	for i := 0; i < 100; i++ {
		_, ok := store.Get(uint64(i))
		if !ok {
			t.Fatalf("session %d should exist after GC", i)
		}
	}
}

func TestKeyStoreGet(t *testing.T) {
	ks := MapKeyStore{
		"key1": []byte("secret1"),
		"key2": []byte("secret2"),
	}

	if string(ks.Get("key1")) != "secret1" {
		t.Fatal("Get key1 failed")
	}
	if string(ks.Get("key2")) != "secret2" {
		t.Fatal("Get key2 failed")
	}
	if ks.Get("nonexistent") != nil {
		t.Fatal("expected nil for nonexistent key")
	}
}

func TestGenerateAPIKeyUnique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 10; i++ {
		k, err := GenerateAPIKey()
		if err != nil {
			t.Fatalf("GenerateAPIKey: %v", err)
		}
		if seen[k.ID] {
			t.Fatal("duplicate key ID generated")
		}
		seen[k.ID] = true
		if len(k.Secret) != 32 {
			t.Fatalf("expected 32-byte secret, got %d", len(k.Secret))
		}
	}
}

func TestEncryptDecryptEmpty(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	encrypted, err := Encrypt(key, []byte{})
	if err != nil {
		t.Fatalf("encrypt empty: %v", err)
	}

	decrypted, err := Decrypt(key, encrypted)
	if err != nil {
		t.Fatalf("decrypt empty: %v", err)
	}

	if len(decrypted) != 0 {
		t.Fatal("expected empty decrypted data")
	}
}

func TestEncryptDecryptLarge(t *testing.T) {
	key := make([]byte, KeySize)
	plaintext := make([]byte, 10000)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	encrypted, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	decrypted, err := Decrypt(key, encrypted)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if len(decrypted) != len(plaintext) {
		t.Fatalf("length mismatch: %d vs %d", len(decrypted), len(plaintext))
	}
	for i := range plaintext {
		if decrypted[i] != plaintext[i] {
			t.Fatalf("byte %d mismatch: %d vs %d", i, decrypted[i], plaintext[i])
		}
	}
}

func TestSessionStoreLen(t *testing.T) {
	store := NewSessionStore(SessionConfig{})
	if store.Len() != 0 {
		t.Fatal("new store should be empty")
	}
	store.Set(NewSession(1, "k1", make([]byte, KeySize)))
	store.Set(NewSession(2, "k2", make([]byte, KeySize)))
	if store.Len() != 2 {
		t.Fatalf("expected 2 sessions, got %d", store.Len())
	}
	store.Delete(1)
	if store.Len() != 1 {
		t.Fatalf("expected 1 session, got %d", store.Len())
	}
}

func TestSessionStoreConfig(t *testing.T) {
	cfg := SessionConfig{IdleTimeout: 10 * time.Second}
	store := NewSessionStore(cfg)
	got := store.Config()
	if got.IdleTimeout != 10*time.Second {
		t.Fatalf("expected idle 10s, got %v", got.IdleTimeout)
	}
}
