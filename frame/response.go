package frame

import (
	"fmt"
	"io"

	"github.com/feralbureau/hush-go/session"
	"github.com/feralbureau/hush-go/tlv"
)

// StatusCode represents a Hush response status.
type StatusCode uint8

const (
	StatusSuccess          StatusCode = 0x00
	StatusBadRequest       StatusCode = 0x01
	StatusUnauthenticated  StatusCode = 0x02
	StatusPermissionDenied StatusCode = 0x03
	StatusNotFound         StatusCode = 0x04
	StatusSessionExpired   StatusCode = 0x05
	StatusRateLimited      StatusCode = 0x06
	StatusInternalError    StatusCode = 0x07
)

func (s StatusCode) String() string {
	switch s {
	case StatusSuccess:
		return "success"
	case StatusBadRequest:
		return "bad_request"
	case StatusUnauthenticated:
		return "unauthenticated"
	case StatusPermissionDenied:
		return "permission_denied"
	case StatusNotFound:
		return "not_found"
	case StatusSessionExpired:
		return "session_expired"
	case StatusRateLimited:
		return "rate_limited"
	case StatusInternalError:
		return "internal_error"
	default:
		if s >= 0x80 {
			return fmt.Sprintf("app_error(0x%02x)", byte(s))
		}
		return fmt.Sprintf("unknown(0x%02x)", byte(s))
	}
}

// Response is a decrypted response frame.
type Response struct {
	Status  StatusCode
	Payload *tlv.Map
	Seq     uint32 // sequence number from the frame
}

// EncodeResponse serializes and optionally encrypts a response.
// If key is nil, the payload is plaintext.
func EncodeResponse(key []byte, seq uint32, r *Response) ([]byte, error) {
	var plaintext []byte
	plaintext = append(plaintext, byte(r.Status))

	if r.Payload != nil {
		tlvData := tlv.MustEncodeMap(r.Payload)
		plaintext = append(plaintext, tlvData...)
	}

	if key == nil {
		return plaintext, nil
	}

	encrypted, err := session.Encrypt(key, plaintext)
	if err != nil {
		return nil, fmt.Errorf("frame: encrypt response: %w", err)
	}
	return encrypted, nil
}

// WriteResponse writes a response frame to w.
// If key is nil, the frame is plaintext.
func WriteResponse(w io.Writer, key []byte, seq uint32, r *Response) error {
	data, err := EncodeResponse(key, seq, r)
	if err != nil {
		return err
	}
	_, err = Write(w, seq, data)
	return err
}

// DecryptResponse decrypts a frame (or reads plaintext) and returns the Response.
// If key is nil, frame.Data is treated as plaintext.
func DecryptResponse(key []byte, f *Frame) (*Response, error) {
	var plaintext []byte
	if key == nil {
		plaintext = f.Data
	} else {
		var err error
		plaintext, err = session.Decrypt(key, f.Data)
		if err != nil {
			return nil, fmt.Errorf("frame: decrypt response: %w", err)
		}
	}

	if len(plaintext) < 1 {
		return nil, fmt.Errorf("frame: response too short")
	}

	r := &Response{
		Status: StatusCode(plaintext[0]),
		Seq:    f.SequenceNumber,
	}

	if len(plaintext) > 1 {
		m, err := tlv.DecodeMap(plaintext[1:])
		if err != nil {
			return nil, fmt.Errorf("frame: decode response tlv: %w", err)
		}
		r.Payload = m
	}

	return r, nil
}

// ReadResponse reads, optionally decrypts, and parses a response frame from r.
func ReadResponse(r io.Reader, key []byte) (*Response, error) {
	f, err := Read(r)
	if err != nil {
		return nil, err
	}
	return DecryptResponse(key, f)
}
