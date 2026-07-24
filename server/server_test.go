package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/feralbureau/hush-go/frame"
	"github.com/feralbureau/hush-go/session"
	"github.com/feralbureau/hush-go/tlv"
	"github.com/feralbureau/hush-go/transport"
)

func testServerHelper(t *testing.T, opts ...Option) (int, *session.APIKey, *Server, func()) {
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

	allOpts := append([]Option{WithTLSConfig(tlsCfg)}, opts...)
	srv, err := NewServer(session.MapKeyStore{apiKey.ID: apiKey.Secret}, allOpts...)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	uaddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn, _ := net.ListenUDP("udp", uaddr)
	port := conn.LocalAddr().(*net.UDPAddr).Port

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		srv.ListenAndServeOnConn(ctx, conn)
	}()

	cleanup := func() {
		cancel()
		conn.Close()
	}

	return port, apiKey, srv, cleanup
}

func testClient(t *testing.T, port int, apiKey *session.APIKey) (quic.Connection, *session.Session) {
	t.Helper()

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "hush.test",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := transport.Dial(ctx, fmt.Sprintf("127.0.0.1:%d", port), tlsConf)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		conn.CloseWithError(0, "test")
		t.Fatalf("open stream: %v", err)
	}

	priv, _ := session.GenerateKeyPair()
	sess, err := session.NegotiateClient(ctx, stream, apiKey, priv)
	stream.Close()
	if err != nil {
		conn.CloseWithError(0, "test")
		t.Fatalf("negotiate: %v", err)
	}

	return conn, sess
}

func TestNewServer(t *testing.T) {
	srv, err := NewServer(session.MapKeyStore{})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if srv == nil {
		t.Fatal("expected non-nil server")
	}
	if srv.handlers == nil {
		t.Fatal("expected non-nil handlers map")
	}
}

func TestNewServerMissingTLS(t *testing.T) {
	srv, _ := NewServer(session.MapKeyStore{})
	err := srv.ListenAndServe(context.Background(), ":0")
	if err == nil || err.Error() != "server: TLS config required" {
		t.Fatalf("expected TLS error, got: %v", err)
	}
}

func TestHandleFunc(t *testing.T) {
	srv, _ := NewServer(session.MapKeyStore{})
	handlerCalled := false

	srv.HandleFunc(0x0001, func(ctx context.Context, r *Request) (*frame.Response, error) {
		handlerCalled = true
		return NewResponse(tlv.NewMap().Set("ok", tlv.Bool(true))), nil
	})

	srv.mu.RLock()
	h, ok := srv.handlers[0x0001]
	srv.mu.RUnlock()

	if !ok {
		t.Fatal("handler not registered")
	}
	if h == nil {
		t.Fatal("handler is nil")
	}

	resp, err := h.HandleHush(context.Background(), &Request{
		Request: &frame.Request{Opcode: 0x0001},
	})
	if err != nil {
		t.Fatalf("HandleHush: %v", err)
	}
	if !handlerCalled {
		t.Fatal("handler was not called")
	}
	if resp.Status != frame.StatusSuccess {
		t.Fatalf("expected success, got %d", resp.Status)
	}
	v, _ := resp.Payload.Get("ok")
	okVal := v.Bool()
	if !okVal {
		t.Fatal("expected ok=true")
	}
}

func TestHandle(t *testing.T) {
	srv, _ := NewServer(session.MapKeyStore{})
	srv.Handle(0x0002, HandlerFunc(func(ctx context.Context, r *Request) (*frame.Response, error) {
		return NewResponse(tlv.NewMap()), nil
	}))
	srv.mu.RLock()
	_, ok := srv.handlers[0x0002]
	srv.mu.RUnlock()
	if !ok {
		t.Fatal("Handle did not register handler")
	}
}

func TestErrorResponse(t *testing.T) {
	resp := ErrorResponse(1, "test error")
	if resp.Status != 1 {
		t.Fatalf("expected status 1, got %d", resp.Status)
	}
	errMsg, ok := resp.Payload.GetString("error")
	if !ok || errMsg != "test error" {
		t.Fatalf("expected 'test error', got '%s'", errMsg)
	}
}

func TestNewResponse(t *testing.T) {
	resp := NewResponse(tlv.NewMap().Set("key", tlv.String("val")))
	if resp.Status != frame.StatusSuccess {
		t.Fatalf("expected success, got %d", resp.Status)
	}
	v, _ := resp.Payload.GetString("key")
	if v != "val" {
		t.Fatalf("expected val, got %s", v)
	}
}

func TestSessionIDFromContext(t *testing.T) {
	ctx := context.WithValue(context.Background(), ctxSessionID, uint64(42))
	id, ok := SessionIDFromContext(ctx)
	if !ok {
		t.Fatal("expected ok")
	}
	if id != 42 {
		t.Fatalf("expected 42, got %d", id)
	}

	_, ok = SessionIDFromContext(context.Background())
	if ok {
		t.Fatal("expected !ok for empty context")
	}
}

func TestAPIKeyIDFromContext(t *testing.T) {
	ctx := context.WithValue(context.Background(), ctxAPIKeyID, "test-key")
	id, ok := APIKeyIDFromContext(ctx)
	if !ok {
		t.Fatal("expected ok")
	}
	if id != "test-key" {
		t.Fatalf("expected 'test-key', got '%s'", id)
	}

	_, ok = APIKeyIDFromContext(context.Background())
	if ok {
		t.Fatal("expected !ok for empty context")
	}
}

func TestLoggerOption(t *testing.T) {
	apiKey, _ := session.GenerateAPIKey()
	cert, _ := tls.LoadX509KeyPair("../test-cert.pem", "../test-key.pem")
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}

	srv, _ := NewServer(
		session.MapKeyStore{apiKey.ID: apiKey.Secret},
		WithTLSConfig(tlsCfg),
		WithLogger(nil),
	)
	if srv == nil {
		t.Fatal("expected non-nil server")
	}
	srv.logf("INF", "should not crash with nil logger")
}

func TestNotFoundHandler(t *testing.T) {
	port, apiKey, _, cleanup := testServerHelper(t)
	defer cleanup()

	conn, sess := testClient(t, port, apiKey)
	defer conn.CloseWithError(0, "done")

	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer stream.Close()

	req := &frame.Request{Opcode: 0xFFFF}
	if err := frame.WriteRequest(stream, sess.Key, 1, req); err != nil {
		t.Fatalf("WriteRequest: %v", err)
	}

	resp, err := frame.ReadResponse(stream, sess.Key)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if resp.Status != frame.StatusNotFound {
		t.Fatalf("expected StatusNotFound(%d), got %d", frame.StatusNotFound, resp.Status)
	}
}

func TestPanicRecovery(t *testing.T) {
	port, apiKey, srv, cleanup := testServerHelper(t)
	defer cleanup()

	srv.HandleFunc(0x0001, func(ctx context.Context, r *Request) (*frame.Response, error) {
		panic("test panic")
	})

	conn, sess := testClient(t, port, apiKey)
	defer conn.CloseWithError(0, "done")

	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer stream.Close()

	req := &frame.Request{Opcode: 0x0001}
	if err := frame.WriteRequest(stream, sess.Key, 1, req); err != nil {
		t.Fatalf("WriteRequest: %v", err)
	}

	resp, err := frame.ReadResponse(stream, sess.Key)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if resp.Status != frame.StatusInternalError {
		t.Fatalf("expected StatusInternalError(%d), got %d", frame.StatusInternalError, resp.Status)
	}
}

func TestSessionsConcurrent(t *testing.T) {
	port, apiKey, _, cleanup := testServerHelper(t)
	defer cleanup()

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, sess := testClient(t, port, apiKey)
			defer conn.CloseWithError(0, "done")
			_ = sess
		}()
	}
	wg.Wait()
}

func TestMediaSupport(t *testing.T) {
	apiKey, _ := session.GenerateAPIKey()
	cert, _ := tls.LoadX509KeyPair("../test-cert.pem", "../test-key.pem")
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}

	srv, err := NewServer(
		session.MapKeyStore{apiKey.ID: apiKey.Secret},
		WithTLSConfig(tlsCfg),
		WithMediaSupport("https://media.local"),
	)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	if srv.MediaTokenStore() == nil {
		t.Fatal("MediaTokenStore should not be nil")
	}

	if _, err := srv.IssueMediaToken(1, "track1"); err != nil {
		t.Fatalf("IssueMediaToken: %v", err)
	}

	srv2, _ := NewServer(session.MapKeyStore{}, WithTLSConfig(tlsCfg))
	_, err = srv2.IssueMediaToken(1, "track1")
	if err == nil {
		t.Fatal("expected error without media support")
	}
}

func TestSessionStoreGC(t *testing.T) {
	_, _, srv, cleanup := testServerHelper(t)
	defer cleanup()

	srv.sessions.GC()

	sess1 := session.NewSession(100, "key1", make([]byte, 32))
	sess2 := session.NewSession(200, "key2", make([]byte, 32))
	srv.sessions.Set(sess1)
	srv.sessions.Set(sess2)

	srv.sessions.GC()

	_, ok1 := srv.sessions.Get(100)
	_, ok2 := srv.sessions.Get(200)
	if !ok1 || !ok2 {
		t.Fatal("sessions should still exist (no expiry yet)")
	}
}
