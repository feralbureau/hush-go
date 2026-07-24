// Package media provides session-bound media token management for Hush.
package media

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"
)

// DefaultMaxTokenTTL is the default maximum lifetime for a media token (2 hours).
const DefaultMaxTokenTTL = 2 * time.Hour

// Token represents a media access token.
type Token struct {
	ID        [16]byte
	TrackID   string    // e.g. "sc:2266990262"
	HLSURL    string    // original HLS playlist URL (for proxy fetching)
	CreatedAt time.Time // last validation time, extended on each Validate()
	IssuedAt  time.Time // original issuance time, for absolute TTL cap
	SessionID uint64    // session that created this token
}

// TokenStore manages media tokens and their validation.
type TokenStore struct {
	mu              sync.Mutex
	ValidateSession func(sessionID uint64) bool
	tokens          map[[16]byte]*Token
	MaxTokenTTL     time.Duration // maximum lifetime from IssuedAt (0 = DefaultMaxTokenTTL)
}

// NewTokenStore creates a new media token store.
// validateSession is optional (may be nil). When set, it is used by Validate
// to additionally check that the creating session is still alive.
func NewTokenStore(validateSession func(uint64) bool) *TokenStore {
	return &TokenStore{
		ValidateSession: validateSession,
		tokens:          make(map[[16]byte]*Token),
		MaxTokenTTL:     DefaultMaxTokenTTL,
	}
}

// IssueWithHLS creates a new media token with an associated HLS stream URL.
func (ts *TokenStore) IssueWithHLS(sessionID uint64, trackID, hlsURL string) (*Token, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, fmt.Errorf("media: generate token: %w", err)
	}

	tok := &Token{
		ID:        id,
		TrackID:   trackID,
		HLSURL:    hlsURL,
		IssuedAt:  time.Now(),
		CreatedAt: time.Now(),
		SessionID: sessionID,
	}

	ts.mu.Lock()
	ts.tokens[id] = tok
	ts.mu.Unlock()

	return tok, nil
}

// Issue creates a new media token for the given session and track.
func (ts *TokenStore) Issue(sessionID uint64, trackID string) (*Token, error) {
	return ts.IssueWithHLS(sessionID, trackID, "")
}

// LookupHLS returns the HLSURL associated with a token, or empty string
// if the token is unknown. Does NOT validate the token — call Validate first.
func (ts *TokenStore) LookupHLS(tokenID [16]byte) string {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	tok, ok := ts.tokens[tokenID]
	if !ok {
		return ""
	}
	return tok.HLSURL
}

// Validate checks if a media token is still valid and extends CreatedAt.
// A token is valid if:
//   - It exists in the store
//   - Its IssuedAt is within MaxTokenTTL (2 hours)
//   - (optionally) Its creating session is still alive
//
// On success, CreatedAt is bumped to now so actively-streamed content
// does not expire mid-playback.
func (ts *TokenStore) Validate(tokenID [16]byte) bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	tok, ok := ts.tokens[tokenID]
	if !ok {
		return false
	}

	// Hard absolute cap from original issuance time.
	if time.Since(tok.IssuedAt) > ts.MaxTokenTTL {
		delete(ts.tokens, tokenID)
		return false
	}

	// Optional session liveness check.
	if ts.ValidateSession != nil && !ts.ValidateSession(tok.SessionID) {
		delete(ts.tokens, tokenID)
		return false
	}

	// Extend CreatedAt so actively-streamed tokens stay alive.
	tok.CreatedAt = time.Now()

	return true
}

// Exists is a lightweight check — returns true if the token is in the store
// regardless of TTL or session state. This is used for HLS segment proxying
// where segments should be served after the manifest was validated.
func (ts *TokenStore) Exists(tokenID [16]byte) bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	_, ok := ts.tokens[tokenID]
	return ok
}

// RevokeBySession removes all tokens for a given session.
func (ts *TokenStore) RevokeBySession(sessionID uint64) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	for id, tok := range ts.tokens {
		if tok.SessionID == sessionID {
			delete(ts.tokens, id)
		}
	}
}

// GC removes tokens that have exceeded MaxTokenTTL since issuance.
func (ts *TokenStore) GC() {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	for id, tok := range ts.tokens {
		if time.Since(tok.IssuedAt) > ts.MaxTokenTTL {
			delete(ts.tokens, id)
		}
	}
}

// MediaURLBuilder constructs HTTPS URLs for media delivery.
type MediaURLBuilder struct {
	BaseURL    string
	TokenStore *TokenStore
}

// NewMediaURLBuilder creates a new URL builder.
func NewMediaURLBuilder(baseURL string, ts *TokenStore) *MediaURLBuilder {
	return &MediaURLBuilder{
		BaseURL:    baseURL,
		TokenStore: ts,
	}
}

// BuildURL creates a media URL for a given token and track.
func (b *MediaURLBuilder) BuildURL(tokenID [16]byte, trackID string) string {
	return fmt.Sprintf("%s/media/%x/%s", b.BaseURL, tokenID, trackID)
}
