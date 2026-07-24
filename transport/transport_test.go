package transport

import (
	"testing"
)

func TestALPN(t *testing.T) {
	if ALPN != "hush/1" {
		t.Fatalf("expected ALPN hush/1, got %s", ALPN)
	}
}
