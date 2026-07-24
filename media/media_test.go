package media

import (
	"sync"
	"testing"
)

func TestTokenIssueAndValidate(t *testing.T) {
	ts := NewTokenStore(func(sessionID uint64) bool { return true })

	tok, err := ts.Issue(1, "track-abc")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if tok.TrackID != "track-abc" {
		t.Fatalf("expected track-abc, got %s", tok.TrackID)
	}
	if tok.SessionID != 1 {
		t.Fatalf("expected session 1, got %d", tok.SessionID)
	}
	if tok.CreatedAt.IsZero() {
		t.Fatal("expected non-zero CreatedAt")
	}

	if !ts.Validate(tok.ID) {
		t.Fatal("expected token to be valid")
	}
}

func TestTokenInvalid(t *testing.T) {
	ts := NewTokenStore(func(sessionID uint64) bool { return true })

	var fakeID [16]byte
	fakeID[0] = 0xFF

	if ts.Validate(fakeID) {
		t.Fatal("expected fake token to be invalid")
	}
}

func TestTokenSessionRejected(t *testing.T) {
	ts := NewTokenStore(func(sessionID uint64) bool { return false })

	tok, err := ts.Issue(1, "track-xyz")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if ts.Validate(tok.ID) {
		t.Fatal("expected token to be invalid when session is rejected")
	}
}

func TestTokenSessionNilCheck(t *testing.T) {
	ts := NewTokenStore(nil)

	tok, err := ts.Issue(42, "track-nil")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if !ts.Validate(tok.ID) {
		t.Fatal("expected token to be valid with nil session validator")
	}
}

func TestRevokeBySession(t *testing.T) {
	ts := NewTokenStore(func(sessionID uint64) bool { return true })

	tok1, _ := ts.Issue(1, "track-a")
	tok2, _ := ts.Issue(1, "track-b")
	tok3, _ := ts.Issue(2, "track-c")

	ts.RevokeBySession(1)

	if ts.Validate(tok1.ID) {
		t.Fatal("expected tok1 to be revoked")
	}
	if ts.Validate(tok2.ID) {
		t.Fatal("expected tok2 to be revoked")
	}
	if !ts.Validate(tok3.ID) {
		t.Fatal("expected tok3 to remain valid")
	}
}

func TestConcurrentIssue(t *testing.T) {
	ts := NewTokenStore(func(sessionID uint64) bool { return true })

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok, err := ts.Issue(1, "track-concurrent")
			if err != nil {
				t.Errorf("Issue: %v", err)
				return
			}
			if !ts.Validate(tok.ID) {
				t.Errorf("concurrent token not valid")
			}
		}()
	}
	wg.Wait()
}

func TestConcurrentRevoke(t *testing.T) {
	ts := NewTokenStore(func(sessionID uint64) bool { return true })

	var tokens [][16]byte
	for i := 0; i < 20; i++ {
		tok, _ := ts.Issue(1, "track")
		tokens = append(tokens, tok.ID)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		ts.RevokeBySession(1)
	}()
	go func() {
		defer wg.Done()
		ts.RevokeBySession(1)
	}()
	wg.Wait()

	for _, id := range tokens {
		if ts.Validate(id) {
			t.Fatal("expected all tokens to be revoked")
		}
	}
}

func TestNewURLBuilder(t *testing.T) {
	ts := NewTokenStore(func(sessionID uint64) bool { return true })
	b := NewMediaURLBuilder("https://media.example.com", ts)

	if b == nil {
		t.Fatal("expected non-nil builder")
	}
	if b.BaseURL != "https://media.example.com" {
		t.Fatalf("expected base URL, got %s", b.BaseURL)
	}
}

func TestBuildURL(t *testing.T) {
	ts := NewTokenStore(func(sessionID uint64) bool { return true })
	b := NewMediaURLBuilder("https://media.example.com", ts)

	var id [16]byte
	for i := range id {
		id[i] = byte(i)
	}

	url := b.BuildURL(id, "track-42")
	expected := "https://media.example.com/media/000102030405060708090a0b0c0d0e0f/track-42"
	if url != expected {
		t.Fatalf("expected %q, got %q", expected, url)
	}
}

func TestTokenStoreGCTime(t *testing.T) {
	ts := NewTokenStore(func(sessionID uint64) bool {
		// Always valid session, test is about store cleanup
		return true
	})

	tok, _ := ts.Issue(1, "track")

	if !ts.Validate(tok.ID) {
		t.Fatal("token should be valid")
	}

	// No explicit GC in TokenStore, but Validate handles revocation
	// by session rejection
}
