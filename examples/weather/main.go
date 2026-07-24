// Hush example: Weather API.
//
// Server proxies wttr.in (no auth required) through Hush.
// Client queries weather by city name.
//
// Usage:
//   Terminal 1: go run . server
//   Terminal 2: go run . client <key_id> <key_secret_hex> <hush_port> <city>
package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
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
  go run . server                    — start weather server
  go run . client <id> <secret> <port> <city>  — query weather`)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "server":
		runServer()
	case "client":
		if len(os.Args) < 6 {
			log.Fatal("Usage: go run . client <key_id> <key_secret_hex> <hush_port> <city>")
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
		server.WithLogger(server.NewLogger("weather")),
	)
	if err != nil {
		log.Fatalf("create server: %v", err)
	}

	srv.HandleFunc(0x0001, func(ctx context.Context, r *server.Request) (*frame.Response, error) {
		city, _ := r.Payload.GetString("city")
		if city == "" {
			return server.ErrorResponse(frame.StatusBadRequest, "city required"), nil
		}

		httpCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		req, _ := http.NewRequestWithContext(httpCtx, "GET", "https://wttr.in/"+city+"?format=%C+%t+%w+%h", nil)
		req.Header.Set("User-Agent", "curl/8.0")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return server.ErrorResponse(frame.StatusInternalError, fmt.Sprintf("fetch failed: %v", err)), nil
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)

		return server.NewResponse(tlv.NewMap().
			Set("city", tlv.String(city)).
			Set("weather", tlv.String(string(body)))), nil
	})

	// Listen on a known port so we can print it
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn, _ := net.ListenUDP("udp", addr)
	hushPort := conn.LocalAddr().(*net.UDPAddr).Port

	fmt.Printf("╔════════════════════════════════════╗\n")
	fmt.Printf("║     Hush Weather Example           ║\n")
	fmt.Printf("╚════════════════════════════════════╝\n")
	fmt.Printf("Key ID:     %s\n", apiKey.ID)
	fmt.Printf("Key Secret: %x\n", apiKey.Secret)
	fmt.Printf("Hush Port:  %d\n\n", hushPort)
	fmt.Printf("Try: go run . client %s %x %d London\n", apiKey.ID, apiKey.Secret, hushPort)

	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt)
	if err := srv.ListenAndServeOnConn(ctx, conn); err != nil {
		log.Fatal(err)
	}
}

func runClient(keyID, keySecretHex, port, city string) {
	secret, err := hex.DecodeString(keySecretHex)
	if err != nil {
		log.Fatalf("bad secret hex: %v", err)
	}

	key := &session.APIKey{ID: keyID, Secret: secret}
	tlsConf := &tls.Config{InsecureSkipVerify: true, ServerName: "hush.test"}
	addr := "127.0.0.1:" + port

	c, err := client.Dial(context.Background(), addr, key,
		client.WithTLSConfig(tlsConf))
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := c.Do(ctx, 0x0001, tlv.NewMap().Set("city", tlv.String(city)))
	if err != nil {
		log.Fatalf("request: %v", err)
	}
	if resp.Status != 0 {
		errMsg, _ := resp.Payload.GetString("error")
		log.Fatalf("error: %s", errMsg)
	}

	weather, _ := resp.Payload.GetString("weather")
	fmt.Printf("\n🌍  %s\n", city)
	fmt.Printf("🌤   %s\n", weather)
}
