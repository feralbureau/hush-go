package session

import (
	"context"
	"crypto/ecdh"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/quic-go/quic-go"
)

// APIKey represents a pre-shared API key used for authentication.
type APIKey struct {
	ID     string // public identifier
	Secret []byte // 32-byte secret key
}

// NegotiateClient performs the client side of the session handshake over a QUIC stream.
func NegotiateClient(ctx context.Context, stream quic.Stream, key *APIKey, clientPriv *ecdh.PrivateKey) (*Session, error) {
	clientPub := clientPriv.PublicKey().Bytes()

	buf := make([]byte, 2+len(key.ID)+PubKeySize)
	binary.BigEndian.PutUint16(buf[:2], uint16(len(key.ID)))
	copy(buf[2:], key.ID)
	copy(buf[2+len(key.ID):], clientPub)

	if _, err := stream.Write(buf); err != nil {
		return nil, fmt.Errorf("negotiate: send init: %w", err)
	}

	resp := make([]byte, PubKeySize+8)
	if _, err := io.ReadFull(stream, resp); err != nil {
		return nil, fmt.Errorf("negotiate: read response: %w", err)
	}

	serverPubKey := resp[:PubKeySize]
	sessionID := binary.BigEndian.Uint64(resp[PubKeySize:])

	serverPub, err := ecdh.X25519().NewPublicKey(serverPubKey)
	if err != nil {
		return nil, fmt.Errorf("negotiate: invalid server pubkey: %w", err)
	}

	shared, err := SharedSecret(clientPriv, serverPub)
	if err != nil {
		return nil, fmt.Errorf("negotiate: shared secret: %w", err)
	}

	sessionKey, err := DeriveSessionKey(shared, key.Secret)
	if err != nil {
		return nil, fmt.Errorf("negotiate: derive key: %w", err)
	}

	sess := NewSession(sessionID, key.ID, sessionKey)
	return sess, nil
}

// APIKeyStore is an interface for looking up API keys by ID.
type APIKeyStore interface {
	Get(id string) []byte
}

// MapKeyStore is a simple in-memory API key store backed by a map.
type MapKeyStore map[string][]byte

func (m MapKeyStore) Get(id string) []byte { return m[id] }

// NegotiateServer performs the server side of the session handshake over a QUIC stream.
func NegotiateServer(ctx context.Context, stream quic.Stream, serverPriv *ecdh.PrivateKey, keyStore APIKeyStore, nextSessionID func() uint64) (*Session, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(stream, header); err != nil {
		return nil, fmt.Errorf("negotiate: read header: %w", err)
	}
	keyLen := binary.BigEndian.Uint16(header)
	if keyLen == 0 {
		return nil, fmt.Errorf("negotiate: empty api key id")
	}
	if keyLen > 256 {
		return nil, fmt.Errorf("negotiate: api key id too long (%d bytes, max 256)", keyLen)
	}

	keyBuf := make([]byte, keyLen+PubKeySize)
	if _, err := io.ReadFull(stream, keyBuf); err != nil {
		return nil, fmt.Errorf("negotiate: read key+pub: %w", err)
	}

	apiKeyID := string(keyBuf[:keyLen])
	clientPubKey := keyBuf[keyLen:]

	apiKeySecret := keyStore.Get(apiKeyID)
	if apiKeySecret == nil {
		return nil, fmt.Errorf("negotiate: unknown api key id %q", apiKeyID)
	}

	clientPub, err := ecdh.X25519().NewPublicKey(clientPubKey)
	if err != nil {
		return nil, fmt.Errorf("negotiate: invalid client pubkey: %w", err)
	}

	serverPub := serverPriv.PublicKey().Bytes()
	sessionID := nextSessionID()

	shared, err := SharedSecret(serverPriv, clientPub)
	if err != nil {
		return nil, fmt.Errorf("negotiate: shared secret: %w", err)
	}

	sessionKey, err := DeriveSessionKey(shared, apiKeySecret)
	if err != nil {
		return nil, fmt.Errorf("negotiate: derive key: %w", err)
	}

	resp := make([]byte, PubKeySize+8)
	copy(resp[:PubKeySize], serverPub)
	binary.BigEndian.PutUint64(resp[PubKeySize:], sessionID)

	if _, err := stream.Write(resp); err != nil {
		return nil, fmt.Errorf("negotiate: send response: %w", err)
	}

	sess := NewSession(sessionID, apiKeyID, sessionKey)
	return sess, nil
}

// GenerateAPIKey creates a new random API key (32 bytes hex-encoded).
func GenerateAPIKey() (*APIKey, error) {
	secret, err := RandomBytes(32)
	if err != nil {
		return nil, err
	}
	idBytes, err := RandomBytes(8)
	if err != nil {
		return nil, err
	}
	return &APIKey{
		ID:     fmt.Sprintf("%x", idBytes),
		Secret: secret,
	}, nil
}
