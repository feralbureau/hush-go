package server

import (
	"context"
	"fmt"
	"io"


	"github.com/feralbureau/hush-go/frame"
	"github.com/feralbureau/hush-go/tlv"
)

// Handler is the interface for handling Hush requests.
type Handler interface {
	// HandleHush processes a decoded request and returns a response.
	// The context carries the session ID and API key ID via values.
	HandleHush(ctx context.Context, req *Request) (*frame.Response, error)
}

// HandlerFunc is a function adapter for Handler.
type HandlerFunc func(ctx context.Context, req *Request) (*frame.Response, error)

func (f HandlerFunc) HandleHush(ctx context.Context, req *Request) (*frame.Response, error) {
	return f(ctx, req)
}

// StreamHandler handles long-lived streaming requests (e.g., event subscriptions).
// The handler takes full control of the stream lifecycle including writing responses
// and closing. When this is used, the server will NOT call WriteResponse or Close.
type StreamHandler interface {
	Handler
	HandleHushStream(ctx context.Context, req *Request, stream io.ReadWriteCloser, key []byte) error
}

// StreamHandlerFunc is a function adapter for StreamHandler.
type StreamHandlerFunc func(ctx context.Context, req *Request, stream io.ReadWriteCloser, key []byte) error

func (f StreamHandlerFunc) HandleHushStream(ctx context.Context, req *Request, stream io.ReadWriteCloser, key []byte) error {
	return f(ctx, req, stream, key)
}

// HandleHush implements Handler by returning an error — StreamHandlerFunc should
// be registered via HandleStream, not Handle.
func (f StreamHandlerFunc) HandleHush(ctx context.Context, req *Request) (*frame.Response, error) {
	return nil, fmt.Errorf("stream handler registered as regular handler")
}

// Request wraps a decoded frame.Request with session metadata.
type Request struct {
	*frame.Request
	SessionID uint64
	APIKeyID  string
}

// Context keys.
type ctxKey string

const (
	ctxSessionID ctxKey = "session_id"
	ctxAPIKeyID  ctxKey = "api_key_id"
)

// SessionIDFromContext extracts the session ID from the context.
func SessionIDFromContext(ctx context.Context) (uint64, bool) {
	v := ctx.Value(ctxSessionID)
	if v == nil {
		return 0, false
	}
	id, ok := v.(uint64)
	return id, ok
}

// APIKeyIDFromContext extracts the API key ID from the context.
func APIKeyIDFromContext(ctx context.Context) (string, bool) {
	v := ctx.Value(ctxAPIKeyID)
	if v == nil {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// NewResponse is a convenience constructor for a successful response with a payload.
func NewResponse(payload *tlv.Map) *frame.Response {
	return &frame.Response{
		Status:  frame.StatusSuccess,
		Payload: payload,
	}
}

// ErrorResponse creates an error response with a message in the payload.
func ErrorResponse(code frame.StatusCode, message string) *frame.Response {
	return &frame.Response{
		Status: code,
		Payload: tlv.NewMap().
			Set("error", tlv.String(message)),
	}
}
