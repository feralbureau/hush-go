// Package transport provides QUIC connection helpers for Hush.
package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/quic-go/quic-go"
)

// DefaultALPN is the default Application-Layer Protocol Negotiation string for Hush.
// Override by setting transport.ALPN before dialing or listening.
var DefaultALPN = "hush/1"

// ALPN is a shorthand for DefaultALPN (kept for backward compat).
const ALPN = "hush/1"

// Dial establishes a QUIC connection to the given address.
// Uses the configured ALPN from the TLS config (falls back to DefaultALPN).
func Dial(ctx context.Context, addr string, tlsConf *tls.Config) (quic.Connection, error) {
	if tlsConf == nil {
		tlsConf = &tls.Config{}
	}
	tlsConf = tlsConf.Clone()
	if len(tlsConf.NextProtos) == 0 {
		tlsConf.NextProtos = []string{DefaultALPN}
	}

	conn, err := quic.DialAddr(ctx, addr, tlsConf, nil)
	if err != nil {
		return nil, fmt.Errorf("transport: dial %s: %w", addr, err)
	}
	return conn, nil
}

// Listen creates a QUIC listener.
// Uses the configured ALPN from the TLS config (falls back to DefaultALPN).
func Listen(addr string, tlsConf *tls.Config) (*quic.Listener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("transport: resolve %s: %w", addr, err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("transport: listen udp %s: %w", addr, err)
	}

	tlsConf = tlsConf.Clone()
	if len(tlsConf.NextProtos) == 0 {
		tlsConf.NextProtos = []string{DefaultALPN}
	}

	l, err := quic.Listen(udpConn, tlsConf, nil)
	if err != nil {
		return nil, fmt.Errorf("transport: listen quic: %w", err)
	}
	return l, nil
}
