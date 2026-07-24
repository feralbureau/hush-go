package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/feralbureau/hush-go/client"
	"github.com/feralbureau/hush-go/frame"
	"github.com/feralbureau/hush-go/tlv"
)

func TestStressConcurrentSessionsAndRequests(t *testing.T) {
	port, apiKey, srv, cleanup := testServerHelper(t)
	defer cleanup()

	srv.HandleFunc(0x0001, func(ctx context.Context, r *Request) (*frame.Response, error) {
		v, _ := r.Payload.GetUint64("n")
		return NewResponse(tlv.NewMap().
			Set("reply", tlv.Uint64(v*2)),
		), nil
	})
	srv.HandleFunc(0x0002, func(ctx context.Context, r *Request) (*frame.Response, error) {
		return ErrorResponse(0x80, "test error"), nil
	})

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "hush.test",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	numSessions := 10
	requestsPerSession := 10

	type result struct {
		sessionID  uint64
		seq        int
		status     frame.StatusCode
		err        error
		replyValue uint64
	}

	results := make(chan result, numSessions*requestsPerSession*2)
	var wg sync.WaitGroup

	for s := 0; s < numSessions; s++ {
		wg.Add(1)
		go func(sessionIdx int) {
			defer wg.Done()

			c, err := client.Dial(ctx, fmt.Sprintf("127.0.0.1:%d", port), apiKey, client.WithTLSConfig(tlsConf))
			if err != nil {
				t.Errorf("session %d dial: %v", sessionIdx, err)
				return
			}
			defer c.Close()

			sid := c.SessionID()

			for reqIdx := 0; reqIdx < requestsPerSession; reqIdx++ {
				r, err := c.Do(ctx, 0x0001, tlv.NewMap().Set("n", tlv.Uint64(uint64(reqIdx))))
				if err != nil {
					results <- result{sessionID: sid, seq: reqIdx, err: err}
					continue
				}
				reply, _ := r.Payload.GetUint64("reply")
				results <- result{
					sessionID:  sid,
					seq:        reqIdx,
					status:     r.Status,
					replyValue: reply,
				}

				// Also test error handler
				re, err := c.Do(ctx, 0x0002, tlv.NewMap())
				if err != nil {
					results <- result{sessionID: sid, seq: reqIdx + 100, err: err}
					continue
				}
				results <- result{
					sessionID: sid,
					seq:       reqIdx + 100,
					status:    re.Status,
				}
			}
		}(s)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var successCount, errorCount atomic.Int32
	var unexpectedErrors int32
	seen := make(map[uint64]bool)

	for r := range results {
		if r.err != nil {
			errorCount.Add(1)
			continue
		}
		successCount.Add(1)
		if r.seq < 100 {
			// Normal request
			if r.status != frame.StatusSuccess {
				t.Errorf("session %d seq %d: expected success, got %d", r.sessionID, r.seq, r.status)
				unexpectedErrors++
			}
			if r.replyValue != uint64(r.seq)*2 {
				t.Errorf("session %d seq %d: expected reply %d, got %d", r.sessionID, r.seq, uint64(r.seq)*2, r.replyValue)
				unexpectedErrors++
			}
		} else {
			// Error request
			if r.status != 0x80 {
				unexpectedErrors++
			}
		}
		if !seen[r.sessionID] {
			seen[r.sessionID] = true
		}
	}

	t.Logf("sessions: %d, requests: %d, success: %d, errors: %d, seen sessions: %d",
		numSessions, requestsPerSession, successCount.Load(), errorCount.Load(), len(seen))

	if unexpectedErrors > 0 {
		t.Fatalf("unexpected errors: %d", unexpectedErrors)
	}

	if int(successCount.Load()) != numSessions*requestsPerSession*2 {
		t.Fatalf("expected %d successes, got %d", numSessions*requestsPerSession*2, successCount.Load())
	}

	if len(seen) != numSessions {
		t.Fatalf("expected %d unique sessions, got %d", numSessions, len(seen))
	}
}

func TestStressTLSReconnect(t *testing.T) {
	port, apiKey, srv, cleanup := testServerHelper(t)
	defer cleanup()

	srv.HandleFunc(0x0001, func(ctx context.Context, r *Request) (*frame.Response, error) {
		sid, _ := SessionIDFromContext(ctx)
		return NewResponse(tlv.NewMap().Set("sid", tlv.Uint64(sid))), nil
	})

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "hush.test",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Connect, disconnect, reconnect - verify new session each time
	var lastSessionID uint64
	for i := 0; i < 5; i++ {
		c, err := client.Dial(ctx, fmt.Sprintf("127.0.0.1:%d", port), apiKey, client.WithTLSConfig(tlsConf))
		if err != nil {
			t.Fatalf("dial iteration %d: %v", i, err)
		}

		sid := c.SessionID()
		if sid == lastSessionID {
			t.Fatalf("iteration %d: got same session ID %d", i, sid)
		}
		if sid == 0 {
			t.Fatal("got zero session ID")
		}
		lastSessionID = sid

		resp, err := c.Do(ctx, 0x0001, tlv.NewMap())
		if err != nil {
			t.Fatalf("do iteration %d: %v", i, err)
		}
		respSid, _ := resp.Payload.GetUint64("sid")
		if respSid != sid {
			t.Fatalf("iteration %d: response sid %d != client sid %d", i, respSid, sid)
		}

		c.Close()
	}
}

func TestStressLargePayload(t *testing.T) {
	port, apiKey, srv, cleanup := testServerHelper(t)
	defer cleanup()

	srv.HandleFunc(0x0001, func(ctx context.Context, r *Request) (*frame.Response, error) {
		data, ok := r.Payload.GetBytes("data")
		if !ok {
			return ErrorResponse(1, "missing data"), nil
		}
		return NewResponse(tlv.NewMap().Set("echo", tlv.Bytes(data))), nil
	})

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "hush.test",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := client.Dial(ctx, fmt.Sprintf("127.0.0.1:%d", port), apiKey, client.WithTLSConfig(tlsConf))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	payload := make([]byte, 100000)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	resp, err := c.Do(ctx, 0x0001, tlv.NewMap().Set("data", tlv.Bytes(payload)))
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if resp.Status != frame.StatusSuccess {
		t.Fatalf("expected success, got %d", resp.Status)
	}
	echo, ok := resp.Payload.GetBytes("echo")
	if !ok {
		t.Fatal("expected echo field")
	}
	if len(echo) != len(payload) {
		t.Fatalf("length mismatch: %d vs %d", len(echo), len(payload))
	}
	for i := range payload {
		if echo[i] != payload[i] {
			t.Fatalf("byte %d mismatch", i)
		}
	}
}
