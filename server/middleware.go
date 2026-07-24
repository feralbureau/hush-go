package server

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/feralbureau/hush-go/frame"
)

// Middleware wraps a Handler and returns a new Handler.
//
// Use it for cross-cutting concerns like logging, auth, rate limiting,
// context injection, or metrics.
//
//   func logMiddleware(logger *log.Logger) Middleware {
//       return func(next Handler) Handler {
//           return HandlerFunc(func(ctx context.Context, req *Request) (*frame.Response, error) {
//               start := time.Now()
//               resp, err := next.HandleHush(ctx, req)
//               logger.Printf("[MW] opcode=0x%04x elapsed=%s", req.Opcode, time.Since(start))
//               return resp, err
//           })
//       }
//   }
//
//   server.Use(logMiddleware(logger))
//   server.Handle(OpGetWeather, weatherHandler)
type Middleware func(Handler) Handler

// StreamMiddleware wraps a StreamHandler.
//
// Same contract as Middleware but for streaming handlers.
//
//   server.UseStream(myStreamMiddleware)
//   server.HandleStream(OpEvents, eventsHandler)
type StreamMiddleware func(StreamHandler) StreamHandler

// ── Built-in middleware ───────────────────────────────────

// LoggingMiddleware returns a Middleware that logs every handled request
// with its opcode, elapsed time, and result status.
func LoggingMiddleware(srv *Server) Middleware {
	logger := srv.Logger
	if logger == nil {
		logger = log.Default()
	}
	return func(next Handler) Handler {
		return HandlerFunc(func(ctx context.Context, req *Request) (*frame.Response, error) {
			start := time.Now()
			resp, err := next.HandleHush(ctx, req)
			elapsed := time.Since(start)
			if err != nil {
				logger.Printf("[MW] opcode=0x%04x ERROR elapsed=%s err=%v", req.Opcode, elapsed, err)
			} else if resp != nil {
				logger.Printf("[MW] opcode=0x%04x status=%d elapsed=%s", req.Opcode, resp.Status, elapsed)
			} else {
				logger.Printf("[MW] opcode=0x%04x elapsed=%s", req.Opcode, elapsed)
			}
			return resp, err
		})
	}
}

// RecoveryMiddleware catches panics in downstream handlers.
func RecoveryMiddleware(onPanic func(req *Request, recovered any)) Middleware {
	if onPanic == nil {
		onPanic = func(req *Request, recovered any) {
			log.Printf("[MW] PANIC opcode=0x%04x session=%d: %v", req.Opcode, req.SessionID, recovered)
		}
	}
	return func(next Handler) Handler {
		return HandlerFunc(func(ctx context.Context, req *Request) (*frame.Response, error) {
			defer func() {
				if r := recover(); r != nil {
					onPanic(req, r)
				}
			}()
			return next.HandleHush(ctx, req)
		})
	}
}

// ContextMiddleware injects arbitrary key-value pairs into the context.
//
//   type ctxDB struct{}
//   server.Use(ContextMiddleware(ctxDB{}, db))
func ContextMiddleware(key, val any) Middleware {
	return func(next Handler) Handler {
		return HandlerFunc(func(ctx context.Context, req *Request) (*frame.Response, error) {
			ctx = context.WithValue(ctx, key, val)
			return next.HandleHush(ctx, req)
		})
	}
}

// RateLimitMiddleware drops requests that exceed the given per-key limit.
// keyFn extracts the rate-limit key from the request.
//
//   limiter := NewSlidingWindowLimiter(100, time.Minute)
//   server.Use(RateLimitMiddleware(limiter, func(req *Request) string {
//       return "session:" + fmt.Sprint(req.SessionID)
//   }))
func RateLimitMiddleware(limiter *SlidingWindowLimiter, keyFn func(*Request) string) Middleware {
	return func(next Handler) Handler {
		return HandlerFunc(func(ctx context.Context, req *Request) (*frame.Response, error) {
			if !limiter.Allow(keyFn(req)) {
				return ErrorResponse(frame.StatusRateLimited, "rate limit exceeded"), nil
			}
			return next.HandleHush(ctx, req)
		})
	}
}

// RateLimitBySession limits requests per session ID.
//
//   limiter := NewSlidingWindowLimiter(100, time.Minute)
//   server.Use(RateLimitBySession(limiter))
func RateLimitBySession(limiter *SlidingWindowLimiter) Middleware {
	return RateLimitMiddleware(limiter, func(req *Request) string {
		return "session:" + fmt.Sprint(req.SessionID)
	})
}

// RateLimitByAPIKey limits requests per API key ID.
// For anonymous sessions, uses "anonymous" as the key.
//
//   limiter := NewSlidingWindowLimiter(1000, time.Minute)
//   server.Use(RateLimitByAPIKey(limiter))
func RateLimitByAPIKey(limiter *SlidingWindowLimiter) Middleware {
	return RateLimitMiddleware(limiter, func(req *Request) string {
		if req.APIKeyID == "" {
			return "key:anonymous"
		}
		return "key:" + req.APIKeyID
	})
}

// RateLimitByRemoteAddr limits requests per remote IP address.
// Requires RemoteAddr in context (set automatically by Server).
func RateLimitByRemoteAddr(limiter *SlidingWindowLimiter) Middleware {
	return func(next Handler) Handler {
		return HandlerFunc(func(ctx context.Context, req *Request) (*frame.Response, error) {
			addr, _ := RemoteAddrFromContext(ctx)
			if addr == "" {
				addr = "unknown"
			}
			if !limiter.Allow("ip:" + addr) {
				return ErrorResponse(frame.StatusRateLimited, "rate limit exceeded"), nil
			}
			return next.HandleHush(ctx, req)
		})
	}
}

// MultiRateLimitMiddleware checks multiple limiters in sequence.
//
//   server.Use(MultiRateLimitMiddleware(
//       NewSlidingWindowLimiter(100, time.Second),
//       NewSlidingWindowLimiter(3000, time.Minute),
//   ))
func MultiRateLimitMiddleware(limiters ...*SlidingWindowLimiter) Middleware {
	return func(next Handler) Handler {
		return HandlerFunc(func(ctx context.Context, req *Request) (*frame.Response, error) {
			key := "session:" + fmt.Sprint(req.SessionID)
			for _, l := range limiters {
				if !l.Allow(key) {
					return ErrorResponse(frame.StatusRateLimited, "rate limit exceeded"), nil
				}
			}
			return next.HandleHush(ctx, req)
		})
	}
}

// RequireAPIKeyID rejects requests where the API key ID doesn't match.
//
//   server.Use(RequireAPIKeyID("service-a", "service-b"))
func RequireAPIKeyID(allowed ...string) Middleware {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, id := range allowed {
		allowedSet[id] = struct{}{}
	}
	return func(next Handler) Handler {
		return HandlerFunc(func(ctx context.Context, req *Request) (*frame.Response, error) {
			if _, ok := allowedSet[req.APIKeyID]; !ok {
				return ErrorResponse(frame.StatusUnauthenticated, "api key not authorized"), nil
			}
			return next.HandleHush(ctx, req)
		})
	}
}
