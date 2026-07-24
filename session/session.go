// Package session provides session negotiation, key exchange, and session management for Hush.
package session

import (
	"sync"
	"time"
)

// Default timeouts (match the original hardcoded values).
const (
	DefaultIdleTimeout = 5 * time.Minute
	DefaultMaxLifetime = 24 * time.Hour
	DefaultGCInterval  = 1 * time.Minute
)

// SessionConfig controls session lifecycle and is used by SessionStore.
// Zero values use the defaults above.
type SessionConfig struct {
	IdleTimeout    time.Duration
	MaxLifetime    time.Duration
	GCInterval     time.Duration
}

// fillDefaults returns a new config with zero values replaced by defaults.
func (c SessionConfig) fillDefaults() SessionConfig {
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = DefaultIdleTimeout
	}
	if c.MaxLifetime <= 0 {
		c.MaxLifetime = DefaultMaxLifetime
	}
	if c.GCInterval <= 0 {
		c.GCInterval = DefaultGCInterval
	}
	return c
}

// Session represents an authenticated Hush session.
type Session struct {
	ID        uint64
	APIKeyID  string
	Key       []byte // AES-256 session key (32 bytes), nil = no encryption
	CreatedAt time.Time
	LastUsed  time.Time
}

// NewSession creates a new session.
func NewSession(id uint64, apiKeyID string, key []byte) *Session {
	now := time.Now()
	return &Session{
		ID:        id,
		APIKeyID:  apiKeyID,
		Key:       key,
		CreatedAt: now,
		LastUsed:  now,
	}
}

// Touch updates the last-used timestamp.
func (s *Session) Touch() {
	s.LastUsed = time.Now()
}

// SessionStore is a thread-safe store for sessions with configurable timeouts.
type SessionStore struct {
	mu       sync.Mutex
	config   SessionConfig
	sessions map[uint64]*Session
}

// NewSessionStore creates a new session store with the given config.
// Pass SessionConfig{} for defaults.
func NewSessionStore(config SessionConfig) *SessionStore {
	config = config.fillDefaults()
	return &SessionStore{
		config:   config,
		sessions: make(map[uint64]*Session),
	}
}

func (ss *SessionStore) Get(id uint64) (*Session, bool) {
	ss.mu.Lock()
	s, ok := ss.sessions[id]
	ss.mu.Unlock()
	return s, ok
}

func (ss *SessionStore) Set(s *Session) {
	ss.mu.Lock()
	ss.sessions[s.ID] = s
	ss.mu.Unlock()
}

func (ss *SessionStore) Delete(id uint64) {
	ss.mu.Lock()
	delete(ss.sessions, id)
	ss.mu.Unlock()
}

// IsExpired checks if a session has exceeded its max lifetime.
func (ss *SessionStore) IsExpired(s *Session) bool {
	return time.Since(s.CreatedAt) > ss.config.MaxLifetime
}

// IsIdleDead checks if a session has been idle long enough.
func (ss *SessionStore) IsIdleDead(s *Session) bool {
	return time.Since(s.LastUsed) > ss.config.IdleTimeout
}

// GC removes expired sessions.
func (ss *SessionStore) GC() {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	for id, s := range ss.sessions {
		if time.Since(s.CreatedAt) > ss.config.MaxLifetime {
			delete(ss.sessions, id)
		}
	}
}

// Len returns the number of active sessions.
func (ss *SessionStore) Len() int {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return len(ss.sessions)
}

// Config returns a copy of the store's config.
func (ss *SessionStore) Config() SessionConfig {
	return ss.config
}
