// Package server implements the Hush protocol server.
// It handles session negotiation, request routing, and panic recovery.
package server

import (
	"context"
	"crypto/ecdh"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/feralbureau/hush-go/frame"
	"github.com/feralbureau/hush-go/media"
	"github.com/feralbureau/hush-go/session"
	"github.com/feralbureau/hush-go/tlv"
	"github.com/feralbureau/hush-go/transport"
)

// Log levels.
const (
	LevelInfo  = "INF"
	LevelWarn  = "WRN"
	LevelError = "ERR"
)

// Server is a Hush protocol server.
type Server struct {
	handlers map[uint16]Handler
	mu       sync.RWMutex
	sessions *session.SessionStore

	middlewares      []Middleware
	streamMiddlewares []StreamMiddleware
	nextID   atomic.Uint64

	keyStore session.APIKeyStore

	serverPriv *ecdh.PrivateKey
	tlsConf    *tls.Config
	mediaStore *media.TokenStore
	mediaURL   *media.MediaURLBuilder

	sessionCfg session.SessionConfig

	Logger *log.Logger
}

// Option configures the server.
type Option func(*Server)

// WithTLSConfig sets the TLS config for the server.
func WithTLSConfig(cfg *tls.Config) Option {
	return func(s *Server) {
		s.tlsConf = cfg
	}
}

// WithMediaSupport enables session-bound media token support.
func WithMediaSupport(baseURL string) Option {
	return func(s *Server) {
		s.mediaStore = media.NewTokenStore(func(sessionID uint64) bool {
			_, ok := s.sessions.Get(sessionID)
			return ok
		})
		s.mediaURL = media.NewMediaURLBuilder(baseURL, s.mediaStore)
	}
}

// WithLogger sets the server's logger.
func WithLogger(l *log.Logger) Option {
	return func(s *Server) {
		s.Logger = l
	}
}

// WithSessionConfig overrides the default session timeouts.
func WithSessionConfig(cfg session.SessionConfig) Option {
	return func(s *Server) {
		s.sessionCfg = cfg
	}
}

// NewServer creates a new Hush server.
func NewServer(keyStore session.APIKeyStore, opts ...Option) (*Server, error) {
	if keyStore == nil {
		keyStore = session.MapKeyStore{}
	}

	priv, err := session.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("server: generate key pair: %w", err)
	}

	s := &Server{
		handlers:   make(map[uint16]Handler),
		sessions:   session.NewSessionStore(session.SessionConfig{}),
		keyStore:   keyStore,
		serverPriv: priv,
	}

	for _, opt := range opts {
		opt(s)
	}

	// Apply config after options so WithSessionConfig can override.
	s.sessions = session.NewSessionStore(s.sessionCfg)
	s.sessionCfg = s.sessions.Config()

	return s, nil
}

// Use adds a Middleware to the server. Middleware is applied to every
// handler registered *after* the call to Use.
func (s *Server) Use(mw Middleware) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.middlewares = append(s.middlewares, mw)
}

// UseStream adds a StreamMiddleware to the server. Applied to every
// streaming handler registered after this call.
func (s *Server) UseStream(mw StreamMiddleware) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.streamMiddlewares = append(s.streamMiddlewares, mw)
}

func (s *Server) logf(level, format string, args ...interface{}) {
	if s.Logger == nil {
		return
	}
	s.Logger.Printf("[%s] "+format, append([]interface{}{level}, args...)...)
}

// Handle registers a handler for a given opcode.
func (s *Server) Handle(opcode uint16, h Handler) {
	// Wrap through middleware chain (in reverse order so first Use = outer layer)
	for i := len(s.middlewares) - 1; i >= 0; i-- {
		h = s.middlewares[i](h)
	}
	s.mu.Lock()
	s.handlers[opcode] = h
	s.mu.Unlock()
}

// HandleFunc registers a handler function for a given opcode.
func (s *Server) HandleFunc(opcode uint16, fn HandlerFunc) {
	h := Handler(fn)
	for i := len(s.middlewares) - 1; i >= 0; i-- {
		h = s.middlewares[i](h)
	}
	s.mu.Lock()
	s.handlers[opcode] = h
	s.mu.Unlock()
}

// HandleStream registers a streaming handler for a given opcode.
func (s *Server) HandleStream(opcode uint16, h StreamHandler) {
	for i := len(s.streamMiddlewares) - 1; i >= 0; i-- {
		h = s.streamMiddlewares[i](h)
	}
	s.mu.Lock()
	s.handlers[opcode] = h
	s.mu.Unlock()
}

// HandleStreamFunc registers a streaming handler function.
func (s *Server) HandleStreamFunc(opcode uint16, fn StreamHandlerFunc) {
	h := StreamHandler(fn)
	for i := len(s.streamMiddlewares) - 1; i >= 0; i-- {
		h = s.streamMiddlewares[i](h)
	}
	s.mu.Lock()
	s.handlers[opcode] = h
	s.mu.Unlock()
}

// ListenAndServe listens on addr and serves Hush connections.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	if s.tlsConf == nil {
		return fmt.Errorf("server: TLS config required")
	}

	listener, err := transport.Listen(addr, s.tlsConf)
	if err != nil {
		return fmt.Errorf("server: listen: %w", err)
	}
	defer listener.Close()

	s.logf(LevelInfo, "listening on %s (ALPN: %s)", addr, transport.ALPN)

	go s.gcLoop(ctx)

	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.logf(LevelWarn, "accept: %v", err)
			continue
		}

		go s.handleConnection(ctx, conn)
	}
}

// ListenAndServeOnConn serves Hush connections on an existing UDP PacketConn.
func (s *Server) ListenAndServeOnConn(ctx context.Context, conn net.PacketConn) error {
	if s.tlsConf == nil {
		return fmt.Errorf("server: TLS config required")
	}

	tlsConf := s.tlsConf.Clone()
	tlsConf.NextProtos = []string{transport.ALPN}

	listener, err := quic.Listen(conn, tlsConf, nil)
	if err != nil {
		return fmt.Errorf("server: listen on conn: %w", err)
	}
	defer listener.Close()

	s.logf(LevelInfo, "listening on %s (ALPN: %s)", conn.LocalAddr(), transport.ALPN)

	go s.gcLoop(ctx)

	for {
		qconn, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.logf(LevelWarn, "accept: %v", err)
			continue
		}
		go s.handleConnection(ctx, qconn)
	}
}

func (s *Server) gcLoop(ctx context.Context) {
	interval := s.sessionCfg.GCInterval
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sessions.GC()
		}
	}
}

func (s *Server) handleConnection(ctx context.Context, conn quic.Connection) {
	defer conn.CloseWithError(0, "bye")

	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return
	}

	sess, err := session.NegotiateServer(
		ctx,
		stream,
		s.serverPriv,
		s.keyStore,
		func() uint64 { return s.nextID.Add(1) },
	)
	stream.Close()
	if err != nil {
		s.logf(LevelWarn, "session[?] negotiate error: %v (remote=%s)", err, conn.RemoteAddr())
		return
	}

	s.sessions.Set(sess)
	defer s.sessions.Delete(sess.ID)

	s.logf(LevelInfo, "session[%d] established key=%s remote=%s", sess.ID, sess.APIKeyID, conn.RemoteAddr())

	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go s.handleStream(ctx, sess, stream)
	}
}

func (s *Server) handleStream(ctx context.Context, sess *session.Session, stream quic.Stream) {
	streamCtx, streamCancel := context.WithCancel(ctx)
	defer streamCancel()

	defer func() {
		if r := recover(); r != nil {
			s.logf(LevelError, "session[%d] panic: %v", sess.ID, r)
			frame.WriteResponse(stream, sess.Key, 0, &frame.Response{
				Status: frame.StatusInternalError,
				Payload: tlv.NewMap().
					Set("error", tlv.String("internal server error")),
			})
		}
	}()

	if s.sessions.IsExpired(sess) || s.sessions.IsIdleDead(sess) {
		frame.WriteResponse(stream, sess.Key, 0, &frame.Response{
			Status: frame.StatusSessionExpired,
		})
		stream.Close()
		return
	}

	sess.Touch()

	req, seq, err := frame.ReadRequest(stream, sess.Key)
	if err != nil {
		s.logf(LevelWarn, "session[%d] read request: %v", sess.ID, err)
		frame.WriteResponse(stream, sess.Key, 0, &frame.Response{
			Status: frame.StatusBadRequest,
			Payload: tlv.NewMap().
				Set("error", tlv.String("bad request")),
		})
		stream.Close()
		return
	}

	s.mu.RLock()
	handler, ok := s.handlers[req.Opcode]
	s.mu.RUnlock()

	if !ok {
		frame.WriteResponse(stream, sess.Key, seq, &frame.Response{
			Status: frame.StatusNotFound,
			Payload: tlv.NewMap().
				Set("opcode", tlv.Uint16(req.Opcode)),
		})
		stream.Close()
		return
	}

	ctx = context.WithValue(ctx, ctxSessionID, sess.ID)
	ctx = context.WithValue(ctx, ctxAPIKeyID, sess.APIKeyID)

	srvReq := &Request{
		Request:   req,
		SessionID: sess.ID,
		APIKeyID:  sess.APIKeyID,
	}

	// Streaming handler — full stream control.
	if streamHandler, ok := handler.(StreamHandler); ok {
		if err := streamHandler.HandleHushStream(streamCtx, srvReq, stream, sess.Key); err != nil {
			s.logf(LevelError, "session[%d] opcode=0x%04x stream error: %v", sess.ID, req.Opcode, err)
		}
		stream.Close()
		return
	}

	// Normal request-response handler.
	start := time.Now()
	resp, err := handler.HandleHush(ctx, srvReq)
	elapsed := time.Since(start)

	if err != nil {
		s.logf(LevelError, "session[%d] opcode=0x%04x handler error (%s): %v", sess.ID, req.Opcode, elapsed, err)
		frame.WriteResponse(stream, sess.Key, seq, &frame.Response{
			Status: frame.StatusInternalError,
			Payload: tlv.NewMap().
				Set("error", tlv.String("internal error")),
		})
		stream.Close()
		return
	}

	s.logf(LevelInfo, "session[%d] opcode=0x%04x status=%d elapsed=%s", sess.ID, req.Opcode, resp.Status, elapsed)

	if err := frame.WriteResponse(stream, sess.Key, seq, resp); err != nil {
		s.logf(LevelError, "session[%d] write response: %v", sess.ID, err)
	}
	stream.Close()
}

// SessionStore returns the session store.
func (s *Server) SessionStore() *session.SessionStore {
	return s.sessions
}

// MediaTokenStore returns the media token store, if media support is enabled.
func (s *Server) MediaTokenStore() *media.TokenStore {
	return s.mediaStore
}

// IssueMediaToken creates a media token for a given session and track.
func (s *Server) IssueMediaToken(sessionID uint64, trackID string) (*media.Token, error) {
	if s.mediaStore == nil {
		return nil, fmt.Errorf("server: media support not enabled")
	}
	return s.mediaStore.Issue(sessionID, trackID)
}
