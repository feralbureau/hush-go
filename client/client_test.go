package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/feralbureau/hush-go/frame"
	"github.com/feralbureau/hush-go/server"
	"github.com/feralbureau/hush-go/session"
	"github.com/feralbureau/hush-go/tlv"
)

func startTestServer(t *testing.T) (int, *session.APIKey, func()) {
	t.Helper()

	apiKey, err := session.GenerateAPIKey()
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}

	cert, err := tls.LoadX509KeyPair("../test-cert.pem", "../test-key.pem")
	if err != nil {
		t.Fatalf("load cert: %v", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	ks := session.MapKeyStore{apiKey.ID: apiKey.Secret}
	srv, err := server.NewServer(ks, server.WithTLSConfig(tlsCfg))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	srv.HandleFunc(0x0101, func(ctx context.Context, r *server.Request) (*frame.Response, error) {
		return server.NewResponse(tlv.NewMap().
			Set("echo", tlv.String("ok")).
			Set("session_id", tlv.Uint64(r.SessionID)),
		), nil
	})

	uaddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}
	conn, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}

	port := conn.LocalAddr().(*net.UDPAddr).Port
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		srv.ListenAndServeOnConn(ctx, conn)
	}()

	cleanup := func() {
		cancel()
		conn.Close()
	}

	return port, apiKey, cleanup
}

func TestDialSuccess(t *testing.T) {
	port, apiKey, cleanup := startTestServer(t)
	defer cleanup()

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "hush.test",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, err := Dial(ctx, fmt.Sprintf("127.0.0.1:%d", port), apiKey, WithTLSConfig(tlsConf))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if c.SessionID() == 0 {
		t.Fatal("expected non-zero session ID")
	}
}

func TestDoEchoRequest(t *testing.T) {
	port, apiKey, cleanup := startTestServer(t)
	defer cleanup()

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "hush.test",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, err := Dial(ctx, fmt.Sprintf("127.0.0.1:%d", port), apiKey, WithTLSConfig(tlsConf))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	resp, err := c.Do(ctx, 0x0101, tlv.NewMap().Set("test", tlv.String("value")))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}

	if resp.Status != frame.StatusSuccess {
		t.Fatalf("expected success, got status=%d", resp.Status)
	}

	echo, _ := resp.Payload.GetString("echo")
	if echo != "ok" {
		t.Fatalf("expected 'ok', got '%s'", echo)
	}

	sid, _ := resp.Payload.GetUint64("session_id")
	if sid == 0 {
		t.Fatal("expected non-zero session_id")
	}
}

func TestDoBeforeDial(t *testing.T) {
	c := &Client{apiKey: &session.APIKey{ID: "test", Secret: make([]byte, 32)}}
	_, err := c.Do(context.Background(), 0x0001, tlv.NewMap())
	if err == nil || err.Error() != "client: not dialed" {
		t.Fatalf("expected 'not dialed' error, got: %v", err)
	}
}

func TestCloseIdempotent(t *testing.T) {
	port, apiKey, cleanup := startTestServer(t)
	defer cleanup()

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "hush.test",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, err := Dial(ctx, fmt.Sprintf("127.0.0.1:%d", port), apiKey, WithTLSConfig(tlsConf))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	c.Close()
	c.Close()
}

func TestResolveHushAddr(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hush://localhost:9000", "localhost:9000"},
		{"hush://server.example.com", "server.example.com:443"},
		{"127.0.0.1:8080", "127.0.0.1:8080"},
		{"localhost:1234", "localhost:1234"},
	}
	for _, tt := range tests {
		got := resolveHushAddr(tt.input)
		if got != tt.want {
			t.Errorf("resolveHushAddr(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestConcurrentDo(t *testing.T) {
	port, apiKey, cleanup := startTestServer(t)
	defer cleanup()

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "hush.test",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := Dial(ctx, fmt.Sprintf("127.0.0.1:%d", port), apiKey, WithTLSConfig(tlsConf))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	var successes atomic.Int32
	done := make(chan struct{})
	for i := 0; i < 20; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			resp, err := c.Do(ctx, 0x0101, tlv.NewMap())
			if err != nil {
				return
			}
			if resp.Status == frame.StatusSuccess {
				successes.Add(1)
			}
		}()
	}
	for i := 0; i < 20; i++ {
		<-done
	}

	if successes.Load() != 20 {
		t.Fatalf("expected 20 successes, got %d", successes.Load())
	}
}
