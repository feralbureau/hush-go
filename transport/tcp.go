// Package transport provides QUIC and TCP connection helpers for Hush.
package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// TCP ALPN for TCP transports.
// When using TCP, the ALPN is still "hush/1" for consistency.
// Cloudflare TCP fallback works without ALPN on the outer TLS.

// DialTCP establishes a TLS-over-TCP connection to the given address.
// The returned *tls.Conn implements io.ReadWriteCloser and can be used
// directly for Hush session negotiation and frame I/O.
//
//   tlsConf := &tls.Config{InsecureSkipVerify: false}
//   conn, err := transport.DialTCP(ctx, "api.myserver.com:8443", tlsConf)
func DialTCP(ctx context.Context, addr string, tlsConf *tls.Config) (*tls.Conn, error) {
	if tlsConf == nil {
		tlsConf = &tls.Config{}
	}
	tlsConf = tlsConf.Clone()
	if len(tlsConf.NextProtos) == 0 {
		tlsConf.NextProtos = []string{DefaultALPN}
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("transport: dial tcp %s: %w", addr, err)
	}

	conn := tls.Client(rawConn, tlsConf)
	if err := conn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("transport: tls handshake %s: %w", addr, err)
	}

	return conn, nil
}

// ListenTCP creates a TLS-over-TCP listener.
// The returned listener yields *tls.Conn values suitable for Hush I/O.
//
//   listener, err := transport.ListenTCP("0.0.0.0:8443", tlsConf)
func ListenTCP(addr string, tlsConf *tls.Config) (net.Listener, error) {
	if tlsConf == nil {
		return nil, fmt.Errorf("transport: tls config required for TCP listen")
	}
	tlsConf = tlsConf.Clone()
	if len(tlsConf.NextProtos) == 0 {
		tlsConf.NextProtos = []string{DefaultALPN}
	}

	listener, err := tls.Listen("tcp", addr, tlsConf)
	if err != nil {
		return nil, fmt.Errorf("transport: listen tcp %s: %w", addr, err)
	}
	return listener, nil
}
