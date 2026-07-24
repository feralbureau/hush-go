// Package client implements the Hush protocol client.
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

// Client is a Hush protocol client.
type Client struct {
	apiKey *session.APIKey
	addr   string

	tlsConf *tls.Config

	mu     sync.Mutex
	conn   quic.Connection
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

// Dial creates a new Hush client and establishes a session.
// addr may be "host:port" or "hush://host:port".
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

// resolveHushAddr normalizes hush:// URIs to host:port.
func resolveHushAddr(addr string) string {
	if strings.HasPrefix(addr, "hush://") {
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

// Do sends a request and returns the response.
func (c *Client) Do(ctx context.Context, opcode uint16, payload *tlv.Map) (*frame.Response, error) {
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

// Close closes the client connection.
func (c *Client) Close() error {
	c.mu.Lock()
	conn := c.conn
	c.conn = nil
	c.dialed = false
	c.mu.Unlock()

	if conn != nil {
		conn.CloseWithError(0, "client close")
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
