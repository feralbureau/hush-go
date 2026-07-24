// Package client implements the Hush protocol client.
// Supports both QUIC (hush://) and TCP (tcps://) transports.
package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"

	"github.com/feralbureau/hush-go/frame"
	"github.com/feralbureau/hush-go/session"
	"github.com/feralbureau/hush-go/tlv"
	"github.com/feralbureau/hush-go/transport"
)

// TransportMode selects the underlying transport.
type TransportMode int

const (
	// TransportQUIC uses QUIC over UDP (default). Fast, multiplexed.
	TransportQUIC TransportMode = iota
	// TransportTCP uses TLS over TCP. Compatible with Cloudflare.
	TransportTCP
)

// Client is a Hush protocol client.
type Client struct {
	apiKey *session.APIKey
	addr   string

	tlsConf *tls.Config
	mode    TransportMode

	mu     sync.Mutex
	conn   quic.Connection   // for QUIC mode
	tcpConn *tls.Conn        // for TCP mode
	sess   *session.Session
	seq    atomic.Uint32
	dialed bool
}

// Option configures the client.
type Option func(*Client)

// WithTLSConfig sets a custom TLS config.
func WithTLSConfig(cfg *tls.Config) Option {
	return func(c *Client) {
		c.tlsConf = cfg
	}
}

// WithTransport sets the transport mode (QUIC or TCP).
func WithTransport(mode TransportMode) Option {
	return func(c *Client) {
		c.mode = mode
	}
}

// Dial creates a new Hush client and establishes a session.
// addr may be "host:port" or "hush://host:port" (QUIC) or "tcps://host:port" (TCP).
//
// By default uses QUIC transport. Use DialTCP or WithTransport(TransportTCP) for TCP.
func Dial(ctx context.Context, addr string, key *session.APIKey, opts ...Option) (*Client, error) {
	c := &Client{
		apiKey: key,
		addr:   resolveHushAddr(addr),
	}
	for _, opt := range opts {
		opt(c)
	}

	if err := c.dial(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// DialTCP creates a client over TLS-over-TCP (useful behind Cloudflare).
//
//   client, err := client.DialTCP(ctx, "api.myserver.com:8443", key)
func DialTCP(ctx context.Context, addr string, key *session.APIKey, opts ...Option) (*Client, error) {
	opts = append(opts, WithTransport(TransportTCP))
	return Dial(ctx, addr, key, opts...)
}

// resolveHushAddr normalizes hush:// and tcps:// URIs to host:port.
func resolveHushAddr(addr string) string {
	if strings.HasPrefix(addr, "hush://") || strings.HasPrefix(addr, "tcps://") {
		if u, err := url.Parse(addr); err == nil {
			host := u.Host
			if u.Port() == "" {
				host += ":443"
			}
			return host
		}
	}
	return addr
}

func (c *Client) dial(ctx context.Context) error {
	if c.tlsConf == nil {
		c.tlsConf = &tls.Config{}
	}

	switch c.mode {
	case TransportTCP:
		return c.dialTCP(ctx)
	default:
		return c.dialQUIC(ctx)
	}
}

func (c *Client) dialQUIC(ctx context.Context) error {
	conn, err := transport.Dial(ctx, c.addr, c.tlsConf)
	if err != nil {
		return fmt.Errorf("client: dial: %w", err)
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		conn.CloseWithError(0, "handshake failed")
		return fmt.Errorf("client: open stream: %w", err)
	}

	priv, err := session.GenerateKeyPair()
	if err != nil {
		stream.Close()
		conn.CloseWithError(0, "keygen failed")
		return fmt.Errorf("client: generate key: %w", err)
	}

	sess, err := session.NegotiateClient(ctx, stream, c.apiKey, priv)
	stream.Close()
	if err != nil {
		conn.CloseWithError(0, "negotiation failed")
		return fmt.Errorf("client: negotiate: %w", err)
	}

	c.mu.Lock()
	c.conn = conn
	c.sess = sess
	c.dialed = true
	c.mu.Unlock()
	return nil
}

func (c *Client) dialTCP(ctx context.Context) error {
	conn, err := transport.DialTCP(ctx, c.addr, c.tlsConf)
	if err != nil {
		return fmt.Errorf("client: dial tcp: %w", err)
	}

	priv, err := session.GenerateKeyPair()
	if err != nil {
		conn.Close()
		return fmt.Errorf("client: generate key: %w", err)
	}

	sess, err := session.NegotiateClient(ctx, conn, c.apiKey, priv)
	if err != nil {
		conn.Close()
		return fmt.Errorf("client: negotiate tcp: %w", err)
	}

	c.mu.Lock()
	c.tcpConn = conn
	c.sess = sess
	c.dialed = true
	c.mu.Unlock()
	return nil
}

// Do sends a request and returns the response.
func (c *Client) Do(ctx context.Context, opcode uint16, payload *tlv.Map) (*frame.Response, error) {
	switch c.mode {
	case TransportTCP:
		return c.doTCP(ctx, opcode, payload)
	default:
		return c.doQUIC(ctx, opcode, payload)
	}
}

func (c *Client) doQUIC(ctx context.Context, opcode uint16, payload *tlv.Map) (*frame.Response, error) {
	c.mu.Lock()
	conn := c.conn
	sess := c.sess
	dialed := c.dialed
	c.mu.Unlock()

	if !dialed {
		return nil, fmt.Errorf("client: not dialed")
	}

	if conn == nil {
		return nil, fmt.Errorf("client: connection closed")
	}

	sess.Touch()

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("client: open stream: %w", err)
	}
	defer stream.Close()

	seq := c.seq.Add(1)

	req := &frame.Request{
		Opcode:  opcode,
		Payload: payload,
	}

	if err := frame.WriteRequest(stream, sess.Key, seq, req); err != nil {
		return nil, fmt.Errorf("client: write request: %w", err)
	}

	resp, err := frame.ReadResponse(stream, sess.Key)
	if err != nil {
		return nil, fmt.Errorf("client: read response: %w", err)
	}

	return resp, nil
}

func (c *Client) doTCP(ctx context.Context, opcode uint16, payload *tlv.Map) (*frame.Response, error) {
	c.mu.Lock()
	tcpConn := c.tcpConn
	sess := c.sess
	dialed := c.dialed
	c.mu.Unlock()

	if !dialed {
		return nil, fmt.Errorf("client: not dialed")
	}

	if tcpConn == nil {
		return nil, fmt.Errorf("client: connection closed")
	}

	sess.Touch()

	seq := c.seq.Add(1)

	req := &frame.Request{
		Opcode:  opcode,
		Payload: payload,
	}

	// TCP Do() is serialized by the mutex to avoid interleaving frames
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := frame.WriteRequest(tcpConn, sess.Key, seq, req); err != nil {
		// Connection likely dead — mark it
		c.tcpConn = nil
		return nil, fmt.Errorf("client: write request: %w", err)
	}

	resp, err := frame.ReadResponse(tcpConn, sess.Key)
	if err != nil {
		c.tcpConn = nil
		return nil, fmt.Errorf("client: read response: %w", err)
	}

	return resp, nil
}

// Close closes the client connection.
func (c *Client) Close() error {
	c.mu.Lock()
	conn := c.conn
	tcpConn := c.tcpConn
	c.conn = nil
	c.tcpConn = nil
	c.dialed = false
	c.mu.Unlock()

	if conn != nil {
		conn.CloseWithError(0, "client close")
	}
	if tcpConn != nil {
		tcpConn.Close()
	}
	return nil
}

// SessionID returns the current session ID.
func (c *Client) SessionID() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sess == nil {
		return 0
	}
	return c.sess.ID
}
