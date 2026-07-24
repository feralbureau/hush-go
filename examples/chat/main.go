// Hush example: Real-time chat.
//
// Uses Hush's built-in event streaming hub for a multi-client chat room.
// Clients subscribe to the "chat" topic and receive messages in real time.
//
// Usage:
//   Terminal 1: go run . server
//   Terminal 2: go run . client <key_id> <key_secret_hex> <hush_port> <nickname>
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/feralbureau/hush-go/client"
	"github.com/feralbureau/hush-go/frame"
	"github.com/feralbureau/hush-go/server"
	"github.com/feralbureau/hush-go/session"
	"github.com/feralbureau/hush-go/tlv"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println(`Usage:
  go run . server                                — start chat server
  go run . client <key_id> <secret> <port> <nick>  — join chat`)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "server":
		runServer()
	case "client":
		if len(os.Args) < 6 {
			log.Fatal("Usage: go run . client <key_id> <key_secret_hex> <hush_port> <nickname>")
		}
		runClient(os.Args[2], os.Args[3], os.Args[4], os.Args[5])
	default:
		log.Fatalf("unknown command: %s", os.Args[1])
	}
}

func runServer() {
	apiKey, _ := session.GenerateAPIKey()
	ks := session.MapKeyStore{apiKey.ID: apiKey.Secret}

	cert, err := tls.LoadX509KeyPair("../../test-cert.pem", "../../test-key.pem")
	if err != nil {
		log.Fatalf("load cert: %v", err)
	}

	srv, err := server.NewServer(ks,
		server.WithTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
		server.WithLogger(log.New(os.Stdout, "chat: ", log.Ltime|log.Lmsgprefix)),
	)
	if err != nil {
		log.Fatalf("create server: %v", err)
	}

	hub := server.NewHub()

	// 0x0001 — Send message
	srv.HandleFunc(0x0001, func(ctx context.Context, r *server.Request) (*frame.Response, error) {
		nick, _ := r.Payload.GetString("nick")
		msg, _ := r.Payload.GetString("message")
		if nick == "" || msg == "" {
			return server.ErrorResponse(frame.StatusBadRequest, "nick and message required"), nil
		}

		hub.Publish("chat", tlv.NewMap().
			Set("nick", tlv.String(nick)).
			Set("message", tlv.String(msg)).
			Set("time", tlv.Timestamp(time.Now())))

		return server.NewResponse(tlv.NewMap().Set("sent", tlv.Bool(true))), nil
	})

	// 0x0002 — Subscribe to chat (streaming)
	srv.HandleStreamFunc(0x0002, hub.SubscribeHandler())

	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn, _ := net.ListenUDP("udp", addr)
	hushPort := conn.LocalAddr().(*net.UDPAddr).Port

	fmt.Printf("╔════════════════════════════════════╗\n")
	fmt.Printf("║     Hush Chat Example              ║\n")
	fmt.Printf("╚════════════════════════════════════╝\n")
	fmt.Printf("Key ID:     %s\n", apiKey.ID)
	fmt.Printf("Key Secret: %x\n", apiKey.Secret)
	fmt.Printf("Hush Port:  %d\n\n", hushPort)
	fmt.Printf("Join: go run . client %s %x %s <nick>\n", apiKey.ID, apiKey.Secret, fmt.Sprint(hushPort))

	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt)
	if err := srv.ListenAndServeOnConn(ctx, conn); err != nil {
		log.Fatal(err)
	}
}

func runClient(keyID, keySecretHex, port, nick string) {
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

	fmt.Printf("\n💬 Joined chat as %s (session %d)\n", nick, c.SessionID())
	fmt.Println("Type a message and press Enter. Ctrl+C to quit.\n")

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		msg := strings.TrimSpace(scanner.Text())
		if msg == "" {
			continue
		}
		if msg == "/quit" || msg == "/exit" {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := c.Do(ctx, 0x0001, tlv.NewMap().
			Set("nick", tlv.String(nick)).
			Set("message", tlv.String(msg)))
		cancel()
		if err != nil {
			fmt.Printf("send error: %v\n", err)
		}
		fmt.Print("> ")
	}
}
