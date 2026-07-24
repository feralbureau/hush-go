# Hush 🔇

**Stealth-first API protocol for Go.**

Hush is a network protocol framework that makes your API invisible to standard
tooling. No HTTP endpoints to discover, no readable request structure, no replay
attacks. It runs over QUIC with a custom ALPN, encodes payloads in a compact
binary TLV format, and encrypts every frame with per-session AES-256-GCM keys.

```
import "github.com/feralbureau/hush-go"
```

---

## Why Hush

| REST problem | Hush fix |
|---|---|
| Anybody can open DevTools and replicate requests | Custom ALPN `hush/1` — HTTP tools can't connect |
| API surface is fully observable | Binary TLV + AEAD — no readable structure |
| Trivial to fuzz and pentest | Session-bound encryption + sequence numbers |
| Unofficial clients are easy to write | Per-session ephemeral ECDH keys make replay useless |
| gRPC is bloated and painful | TLV instead of protobuf, no codegen, no schema files |

You can disable any of these protections when you don't need them (see
[Configuration](#configuration)).

---

## Quick Start

### Prerequisites

- Go 1.26+
- A TLS certificate for local testing:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout test-key.pem -out test-cert.pem -days 3650 -nodes \
  -subj "/CN=hush.test" -addext "subjectAltName=DNS:hush.test,IP:127.0.0.1"
```

### Minimal server

```go
package main

import (
    "context"
    "crypto/tls"
    "log"
    "os"
    "os/signal"

    "github.com/feralbureau/hush-go/frame"
    "github.com/feralbureau/hush-go/server"
    "github.com/feralbureau/hush-go/session"
    "github.com/feralbureau/hush-go/tlv"
)

func main() {
    apiKey, _ := session.GenerateAPIKey()
    keyStore := session.MapKeyStore{apiKey.ID: apiKey.Secret}

    cert, _ := tls.LoadX509KeyPair("test-cert.pem", "test-key.pem")
    tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}

    srv, _ := server.NewServer(keyStore,
        server.WithTLSConfig(tlsCfg),
        server.WithLogger(log.Default()),
    )

    srv.HandleFunc(0x0001, func(ctx context.Context, r *server.Request) (*frame.Response, error) {
        name, _ := r.Payload.GetString("name")
        return server.NewResponse(tlv.NewMap().
            Set("greeting", tlv.String("hello, "+name))), nil
    })

    ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt)
    log.Fatal(srv.ListenAndServe(ctx, ":443"))
}
```

### Minimal client

```go
package main

import (
    "context"
    "crypto/tls"
    "fmt"
    "log"

    "github.com/feralbureau/hush-go/client"
    "github.com/feralbureau/hush-go/session"
    "github.com/feralbureau/hush-go/tlv"
)

func main() {
    key := &session.APIKey{ID: "<id>", Secret: []byte("<secret>")}
    tlsConf := &tls.Config{InsecureSkipVerify: true}

    c, err := client.Dial(context.Background(), "127.0.0.1:443", key,
        client.WithTLSConfig(tlsConf))
    if err != nil {
        log.Fatal(err)
    }
    defer c.Close()

    resp, _ := c.Do(context.Background(), 0x0001,
        tlv.NewMap().Set("name", tlv.String("world")))

    greeting, _ := resp.Payload.GetString("greeting")
    fmt.Println(greeting) // "hello, world"
}
```

---

## Package Overview

```
hush-go/
├── transport/   QUIC dial/listen with configurable ALPN
├── session/     X25519 key exchange, AES-256-GCM, session store
├── frame/       Length-prefixed encrypted/plaintext wire frames
├── tlv/         Binary TLV serialization (string, ints, floats, maps, arrays)
├── client/      High-level client (connect, send, receive)
├── server/      High-level server (TLS, sessions, handler dispatch, streaming)
│   └── stream.go   Built-in event pub/sub hub
└── media/       Session-bound media tokens for HTTP media delivery
```

### `transport` — QUIC connectivity

```go
// Override the ALPN for the protocol (default: "hush/1")
transport.DefaultALPN = "my-app/1"

conn, _ := transport.Dial(ctx, "127.0.0.1:443", tlsCfg)
listener, _ := transport.Listen(":443", tlsCfg)
```

The TLS config passed to Dial/Listen acts as the source for certificates and
ALPN. If `NextProtos` is empty, the transport uses `DefaultALPN`.

### `session` — Key exchange, crypto, configuration

```
POST-QUIC HANDSHAKE:
  Client ──► api_key_id + X25519_pub ──► Server
  Client ◄── X25519_pub + session_id  ◄── Server
  Both: shared = ECDH(priv, peer_pub)
        key = HKDF-SHA256(salt=shared, ikm=api_key_secret, info="hush-v1-key")
```

```go
// Generate API keys
key, _ := session.GenerateAPIKey()

// Low-level handshake
priv, _ := session.GenerateKeyPair()
sess, _ := session.NegotiateClient(ctx, stream, key, priv)

// Key store interface
type APIKeyStore interface {
    Get(id string) []byte
}
store := session.MapKeyStore{key.ID: key.Secret}

// Session store with configurable timeouts
store := session.NewSessionStore(session.SessionConfig{
    IdleTimeout: 5 * time.Minute,
    MaxLifetime: 24 * time.Hour,
    GCInterval:  1 * time.Minute,
})
```

### `frame` — Wire format

Every request/response is a single QUIC stream containing one frame:

```
4 bytes: frame_length (big-endian)
4 bytes: sequence_number (big-endian)
N bytes: frame_data
```

When **encrypted** (`key != nil`):

```
frame_data = nonce (12) || AES-256-GCM ciphertext || tag (16)
```

When **plaintext** (`key == nil`):

```
frame_data = raw plaintext bytes
```

```go
// Encrypted (default)
frame.WriteRequest(stream, key, seq, req)
req, seq, _ := frame.ReadRequest(stream, key)

// Plaintext (no encryption)
frame.WriteRequest(stream, nil, seq, req)
req, seq, _ := frame.ReadRequest(stream, nil)
```

#### Allowed opcode ranges

Opcodes are `uint16`. The convention is:

| Range | Use |
|-------|-----|
| `0x0000` | Reserved (server push events) |
| `0x0001`–`0x00FF` | System |
| `0x0100`–`0x7FFF` | Application |
| `0x8000`–`0xFFFF` | Reserved for future Hush extensions |

### `tlv` — Binary payload serialization

Compact, no schema files, no codegen. The wire format is:

```
type (1 byte) || length (LEB128 varint) || value (length bytes)
```

**Supported types:**

| Type | Go constructor | Go accessor |
|------|---|--|
| String | `tlv.String(s)` | `v.String()` |
| Bytes | `tlv.Bytes(b)` | `v.Bytes()` |
| Uint8 | `tlv.Uint8(n)` | `v.Uint8()` |
| Uint16 | `tlv.Uint16(n)` | `v.Uint16()` |
| Uint32 | `tlv.Uint32(n)` | `v.Uint32()` |
| Uint64 | `tlv.Uint64(n)` | `v.Uint64()` |
| Int32 | `tlv.Int32(n)` | `v.Int32()` |
| Int64 | `tlv.Int64(n)` | `v.Int64()` |
| Float32 | `tlv.Float32(f)` | `v.Float32()` |
| Float64 | `tlv.Float64(f)` | `v.Float64()` |
| Bool | `tlv.Bool(b)` | `v.Bool()` |
| Array | `tlv.Array(vals)` | `v.Array()` |
| Map | `tlv.NewMap().Set(...)` | `v.Map()` |
| Timestamp | `tlv.Timestamp(t)` | `v.Timestamp()` |
| Null | `tlv.Null` | — |

**Maps — the primary payload structure:**

```go
payload := tlv.NewMap().
    Set("name", tlv.String("alice")).
    Set("count", tlv.Uint64(42)).
    Set("nested", tlv.MapValue(tlv.NewMap().
        Set("key", tlv.Bool(true)),
    )).

// Reading
name, _ := payload.GetString("name")
count, _ := payload.GetUint64("count")
nested, _ := payload.GetMap("nested")
```

### `client` — High-level client

```go
c, err := client.Dial(ctx, addr, apiKey, opts...)
resp, err := c.Do(ctx, opcode, payload)
sid := c.SessionID()
c.Close()
```

### `server` — High-level server

```go
srv, _ := server.NewServer(keyStore, opts...)

// Standard request-response handler
srv.HandleFunc(0x0001, func(ctx context.Context, r *server.Request) (*frame.Response, error) {
    return server.NewResponse(tlv.NewMap().Set("ok", tlv.Bool(true))), nil
})

// Streaming handler (full stream control, e.g. event subscriptions)
srv.HandleStreamFunc(0x0002, func(ctx context.Context, r *server.Request,
    stream io.ReadWriteCloser, key []byte) error {
    // write frames to stream
    return nil
})

srv.ListenAndServe(ctx, ":443")

// Or use an existing UDP socket
conn, _ := net.ListenUDP("udp", addr)
srv.ListenAndServeOnConn(ctx, conn)
```

**Server options:**

| Option | Purpose |
|--------|---------|
| `WithTLSConfig(cfg)` | TLS certificates (required) |
| `WithLogger(l)` | Structured logger (nil = silent) |
| `WithSessionConfig(cfg)` | Session timeouts |
| `WithMediaSupport(baseURL)` | Media token store |

### `media` — Media token management

For serving large files (images, audio, HLS streams) over HTTPS, Hush uses
session-bound media tokens. The QUIC session handles API calls; a companion
HTTPS server handles media delivery.

```go
store := media.NewTokenStore(func(sid uint64) bool {
    _, ok := sessionStore.Get(sid)
    return ok
})

// Issue a token bound to a session
tok, _ := store.Issue(sessionID, "track-abc")

// Validate and extend (for initial access)
valid := store.Validate(tok.ID)

// Lightweight existence check (for HLS segment proxying)
exists := store.Exists(tok.ID)

// Absolute TTL (configurable)
store.MaxTokenTTL = 30 * time.Minute

// Build media URLs
builder := media.NewMediaURLBuilder("https://media.example.com", store)
url := builder.BuildURL(tok.ID, "track-abc")
// → "https://media.example.com/media/ab12.../track-abc"
```

---

## Event Streaming

Hush includes a built-in in-memory topic-based pub/sub hub.

```go
hub := server.NewHub()

// Register handlers
srv.HandleFunc(0x0401, hub.PublishHandler())
srv.HandleStreamFunc(0x0402, hub.SubscribeHandler())
srv.HandleFunc(0x0403, hub.ListTopicsHandler())

// Publish from anywhere
hub.Publish("alerts", tlv.NewMap().Set("level", tlv.String("info")))
```

### Client side

```go
// Subscribe to a topic (streaming — stays open)
// Subscribe creates a long-lived stream that pushes events as they arrive.
// The client receives frames with status=0 and the event payload.

// Publish an event (standard request-response)
resp, _ := c.Do(ctx, 0x0401, tlv.NewMap().
    Set("topic", tlv.String("alerts")).
    Set("payload", tlv.MapValue(tlv.NewMap().
        Set("level", tlv.String("info")),
    )),
)

// List active topics
resp, _ := c.Do(ctx, 0x0403, nil)
```

---

## Configuration

Everything in Hush is configurable. Here's every tuning point:

### Encryption on/off

Pass `nil` instead of a session key to read/write plaintext frames:

```go
frame.WriteRequest(stream, nil, seq, req)     // no encryption
req, seq, _ := frame.ReadRequest(stream, nil)  // no decryption
```

### Session timeouts

```go
srv, _ := server.NewServer(ks,
    server.WithSessionConfig(session.SessionConfig{
        IdleTimeout:    10 * time.Minute,   // default: 5m
        MaxLifetime:    48 * time.Hour,      // default: 24h
        GCInterval:     30 * time.Second,    // default: 1m
    }),
)
```

### ALPN

```go
import "github.com/feralbureau/hush-go/transport"

transport.DefaultALPN = "my-custom-proto/1"
```

### Media token TTL

```go
store.MaxTokenTTL = 10 * time.Minute  // default: 2h
```

### Logger

```go
srv, _ := server.NewServer(ks,
    server.WithLogger(log.New(os.Stdout, "hush: ", log.Ltime|log.Lmsgprefix)),
)
```

### Log level format

Server logs use level prefixes: `[INF]`, `[WRN]`, `[ERR]`.

---

## Wire Protocol Reference

### Frame format

```
frame_length (uint32 BE) || frame_data
```

**Encrypted frame_data:**

```
sequence_number (uint32 BE) || nonce (12 bytes) || ciphertext || AEAD tag (16 bytes)
```

**Plaintext frame_data:**

```
sequence_number (uint32 BE) || plaintext
```

### Request plaintext

```
opcode (uint16 BE) || tlv_payload (optional)
```

### Response plaintext

```
status_code (uint8) || tlv_payload (optional)
```

### Status codes

| Code | Name |
|------|------|
| `0x00` | Success |
| `0x01` | Bad request |
| `0x02` | Unauthenticated |
| `0x03` | Permission denied |
| `0x04` | Not found |
| `0x05` | Session expired |
| `0x06` | Rate limited |
| `0x07` | Internal error |
| `0x80+` | Application-defined |

### Session handshake

```
Client → Server:  api_key_id_len (uint16 BE) || api_key_id || X25519_pubkey (32 bytes)
Server → Client:  X25519_pubkey (32 bytes) || session_id (uint64 BE)

Shared secret = ECDH(client_priv, server_pub)
Session key   = HKDF-SHA256(ikm=api_key_secret, salt=shared_secret, info="hush-v1-key")
```

---

## Security Model

| Threat | Mitigation |
|---|---|
| Eavesdropping | TLS 1.3 + AES-256-GCM per frame |
| Replay attacks | Per-frame sequence number, per-session keys |
| API key theft | Keys are PSK for ECDH — never sent after handshake |
| Observability | Custom ALPN, binary wire format, no readable structure |
| Fuzzing | Invalid frames fail AEAD decryption at the transport layer |
| Session hijack | Session ID is tied to ECDH-derived key |

### Tradeoffs

- **Browser support**: Hush uses raw QUIC — browsers can't open WebSocket-style
  connections to it. For web clients, run an HTTPS or WebSocket bridge.
- **Complexity**: QUIC + custom crypto is heavier than plain HTTP. You're trading
  simplicity for stealth.
- **Debugging**: No curl, no Postman, no DevTools. Use the included client, or
  run in plaintext mode (`key == nil`) during development.

---

## Project Structure

```
hush-go/
├── transport/   QUIC dial/listen, configurable ALPN
├── session/     X25519 key exchange, AES-256-GCM, session store, config
├── frame/       Length-prefixed encrypted/plaintext wire frames
├── tlv/         Binary TLV encode/decode, all types
├── client/      High-level client
├── server/      High-level server, handlers, event streaming hub
├── media/       Session-bound media token store
├── test-cert.pem   TLS cert for local testing
└── test-key.pem    TLS key for local testing
```

---

## License

MIT
