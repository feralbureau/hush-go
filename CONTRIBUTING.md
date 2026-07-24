# Contributing to Hush

Thanks for wanting to contribute. Hush is a small, focused project — that's by design. Every addition should earn its keep.

## What fits

Hush is a **protocol framework**, not an application server. Good contributions:

- **Bug fixes** — anything in the 7 core packages
- **Performance** — faster serialization, fewer allocations, smarter crypto
- **Protocol extensions** — only if they're optional and don't bloat the core
- **Tests** — edge cases, fuzzing, interoperability
- **Documentation** — clearer examples, better explanations, fixing gaps
- **Examples** — new complete examples in [`examples/`](examples/) are welcome

What doesn't fit:

- **Application-layer features** — SoundCloud clients, auth dashboards, webhook integrations. Those are examples, not the library.
- **New transports** — unless there's a good case. TCP? WebSocket? Talk about it first.
- **Schema changes** — the TLV wire format and frame structure are set. Breaking changes won't be accepted.

## Before you start

If you're adding a feature or changing behaviour, open an issue first. Saves you writing code that won't merge.

## Running examples

All examples are in [`examples/`](examples/). Test your changes against them:

```bash
# Generate TLS certs first (one time)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout test-key.pem -out test-cert.pem -days 3650 -nodes \
  -subj "/CN=hush.test" -addext "subjectAltName=DNS:hush.test,IP:127.0.0.1"

# Build all examples
go build ./examples/...

# Run a specific example
go run examples/weather/main.go server
go run examples/weather/main.go client <key> <secret> <port> London
```

## PR guidelines

- One change per PR. Small diffs get reviewed faster.
- All existing tests must pass. Add tests for new code.
- Run the examples to verify nothing is broken.
- Follow the existing style. There's no formatter config — just match the surrounding code.
- No vendored dependencies. Hush has two: `quic-go` and `golang.org/x/crypto`. Think hard before adding a third.
- Keep the diff minimal. Don't reformat unrelated code.

## Running tests

```bash
go test ./...
```

The race detector should pass too:

```bash
go test -race -count=1 ./...
```

## Code of conduct

Don't be a jerk.
