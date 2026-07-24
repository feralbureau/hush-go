// Hush example: CRUD notes.
//
// In-memory notes store with Create, List, Get, Update, Delete operations.
//
// Usage:
//   Terminal 1: go run . server
//   Terminal 2: go run . client <key_id> <key_secret_hex> <hush_port>
package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"net"
	"sync"
	"time"

	"github.com/feralbureau/hush-go/frame"
	"github.com/feralbureau/hush-go/server"
	"github.com/feralbureau/hush-go/session"
	"github.com/feralbureau/hush-go/tlv"
	"github.com/feralbureau/hush-go/client"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println(`Usage:
  go run . server                    — start CRUD server
  go run . client <id> <secret> <port>  — interactive CRUD client`)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "server":
		runServer()
	case "client":
		if len(os.Args) < 5 {
			log.Fatal("Usage: go run . client <key_id> <key_secret_hex> <hush_port>")
		}
		runClient(os.Args[2], os.Args[3], os.Args[4])
	default:
		log.Fatalf("unknown command: %s", os.Args[1])
	}
}

// ── Server ──────────────────────────────────────────────────

var (
	mu     sync.Mutex
	notes  = map[uint64]string{}
	nextID uint64 = 1
)

func runServer() {
	apiKey, _ := session.GenerateAPIKey()
	ks := session.MapKeyStore{apiKey.ID: apiKey.Secret}

	cert, err := tls.LoadX509KeyPair("../../test-cert.pem", "../../test-key.pem")
	if err != nil {
		log.Fatalf("load cert: %v", err)
	}

	srv, err := server.NewServer(ks,
		server.WithTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
		server.WithLogger(server.NewLogger("crud")),
	)
	if err != nil {
		log.Fatalf("create server: %v", err)
	}

	// 0x0001 — Create
	srv.HandleFunc(0x0001, func(ctx context.Context, r *server.Request) (*frame.Response, error) {
		text, _ := r.Payload.GetString("text")
		if text == "" {
			return server.ErrorResponse(frame.StatusBadRequest, "text required"), nil
		}

		mu.Lock()
		id := nextID
		nextID++
		notes[id] = text
		mu.Unlock()

		return server.NewResponse(tlv.NewMap().
			Set("id", tlv.Uint64(id))), nil
	})

	// 0x0002 — List
	srv.HandleFunc(0x0002, func(ctx context.Context, r *server.Request) (*frame.Response, error) {
		mu.Lock()
		arr := make([]tlv.Value, 0, len(notes))
		for id, text := range notes {
			arr = append(arr, tlv.MapValue(tlv.NewMap().
				Set("id", tlv.Uint64(id)).
				Set("text", tlv.String(text)),
			))
		}
		mu.Unlock()

		return server.NewResponse(tlv.NewMap().
			Set("notes", tlv.Array(arr)).
			Set("count", tlv.Uint64(uint64(len(arr))))), nil
	})

	// 0x0003 — Get
	srv.HandleFunc(0x0003, func(ctx context.Context, r *server.Request) (*frame.Response, error) {
		id, _ := r.Payload.GetUint64("id")
		if id == 0 {
			return server.ErrorResponse(frame.StatusBadRequest, "id required"), nil
		}

		mu.Lock()
		text, ok := notes[id]
		mu.Unlock()

		if !ok {
			return server.ErrorResponse(frame.StatusNotFound, "note not found"), nil
		}

		return server.NewResponse(tlv.NewMap().
			Set("id", tlv.Uint64(id)).
			Set("text", tlv.String(text))), nil
	})

	// 0x0004 — Update
	srv.HandleFunc(0x0004, func(ctx context.Context, r *server.Request) (*frame.Response, error) {
		id, _ := r.Payload.GetUint64("id")
		if id == 0 {
			return server.ErrorResponse(frame.StatusBadRequest, "id required"), nil
		}
		text, _ := r.Payload.GetString("text")
		if text == "" {
			return server.ErrorResponse(frame.StatusBadRequest, "text required"), nil
		}

		mu.Lock()
		_, ok := notes[id]
		if ok {
			notes[id] = text
		}
		mu.Unlock()

		if !ok {
			return server.ErrorResponse(frame.StatusNotFound, "note not found"), nil
		}

		return server.NewResponse(tlv.NewMap().
			Set("id", tlv.Uint64(id)).
			Set("updated", tlv.Bool(true))), nil
	})

	// 0x0005 — Delete
	srv.HandleFunc(0x0005, func(ctx context.Context, r *server.Request) (*frame.Response, error) {
		id, _ := r.Payload.GetUint64("id")
		if id == 0 {
			return server.ErrorResponse(frame.StatusBadRequest, "id required"), nil
		}

		mu.Lock()
		_, ok := notes[id]
		delete(notes, id)
		mu.Unlock()

		return server.NewResponse(tlv.NewMap().
			Set("deleted", tlv.Bool(ok))), nil
	})

	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn, _ := net.ListenUDP("udp", addr)
	hushPort := conn.LocalAddr().(*net.UDPAddr).Port

	fmt.Printf("╔════════════════════════════════════╗\n")
	fmt.Printf("║     Hush CRUD Notes Example       ║\n")
	fmt.Printf("╚════════════════════════════════════╝\n")
	fmt.Printf("Key ID:     %s\n", apiKey.ID)
	fmt.Printf("Key Secret: %x\n", apiKey.Secret)
	fmt.Printf("Hush Port:  %d\n\n", hushPort)
	fmt.Println("Ops:")
	fmt.Println("  0x0001  Create(text)     → id")
	fmt.Println("  0x0002  List()           → notes[]")
	fmt.Println("  0x0003  Get(id)          → note")
	fmt.Println("  0x0004  Update(id, text) → ok")
	fmt.Println("  0x0005  Delete(id)       → ok")
	fmt.Println()

	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt)
	if err := srv.ListenAndServeOnConn(ctx, conn); err != nil {
		log.Fatal(err)
	}
}

// ── Client ──────────────────────────────────────────────────

func runClient(keyID, keySecretHex, port string) {
	secret, err := hex.DecodeString(keySecretHex)
	if err != nil {
		log.Fatalf("bad secret hex: %v", err)
	}

	key := &session.APIKey{ID: keyID, Secret: secret}
	tlsConf := &tls.Config{InsecureSkipVerify: true, ServerName: "hush.test"}

	c, err := client.Dial(context.Background(), "127.0.0.1:"+port, key,
		client.WithTLSConfig(tlsConf))
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer c.Close()

	fmt.Printf("Session: %d\n\n", c.SessionID())

	// Create some notes
	ids := []uint64{}
	for _, title := range []string{"buy milk", "call mom", "fix the bug"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		resp, err := c.Do(ctx, 0x0001, tlv.NewMap().Set("text", tlv.String(title)))
		cancel()
		if err != nil {
			log.Fatalf("create: %v", err)
		}
		id, _ := resp.Payload.GetUint64("id")
		ids = append(ids, id)
		fmt.Printf("✅ Created note %d: %s\n", id, title)
	}

	// List them
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	resp, _ := c.Do(ctx, 0x0002, nil)
	cancel()
	count, _ := resp.Payload.GetUint64("count")
	fmt.Printf("\n📋 %d notes total\n", count)
	if notesVal, ok := resp.Payload.Get("notes"); ok {
		for _, nv := range notesVal.Array() {
			m := nv.Map()
			id, _ := m.GetUint64("id")
			text, _ := m.GetString("text")
			fmt.Printf("   %d: %s\n", id, text)
		}
	}

	// Update one
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	resp, _ = c.Do(ctx, 0x0004, tlv.NewMap().
		Set("id", tlv.Uint64(ids[0])).
		Set("text", tlv.String("buy milk and eggs")))
	cancel()
	fmt.Printf("\n✏️  Updated note %d\n", ids[0])

	// Get it
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	resp, _ = c.Do(ctx, 0x0003, tlv.NewMap().Set("id", tlv.Uint64(ids[0])))
	cancel()
	text, _ := resp.Payload.GetString("text")
	fmt.Printf("🔍  Note %d: %s\n", ids[0], text)

	// Delete one
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	resp, _ = c.Do(ctx, 0x0005, tlv.NewMap().Set("id", tlv.Uint64(ids[2])))
	cancel()
	fmt.Printf("🗑️  Deleted note %d\n", ids[2])

	// List again
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	resp, _ = c.Do(ctx, 0x0002, nil)
	cancel()
	count, _ = resp.Payload.GetUint64("count")
	fmt.Printf("\n📋 %d notes remaining\n", count)
	if notesVal, ok := resp.Payload.Get("notes"); ok {
		for _, nv := range notesVal.Array() {
			m := nv.Map()
			id, _ := m.GetUint64("id")
			text, _ := m.GetString("text")
			fmt.Printf("   %d: %s\n", id, text)
		}
	}
}
