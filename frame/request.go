package frame

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/feralbureau/hush-go/session"
	"github.com/feralbureau/hush-go/tlv"
)

// Request is a decrypted request frame.
type Request struct {
	Opcode  uint16
	Payload *tlv.Map // optional, may be nil
}

// EncodeRequest serializes and optionally encrypts a request.
// If key is nil, the payload is plaintext (no nonce/tag overhead).
// If key is non-nil, the payload is encrypted with AES-256-GCM.
func EncodeRequest(key []byte, seq uint32, r *Request) ([]byte, error) {
	var plaintext []byte
	opBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(opBuf, r.Opcode)
	plaintext = append(plaintext, opBuf...)

	if r.Payload != nil {
		tlvData := tlv.MustEncodeMap(r.Payload)
		plaintext = append(plaintext, tlvData...)
	}

	if key == nil {
		// No encryption: return plaintext directly
		return plaintext, nil
	}

	encrypted, err := session.Encrypt(key, plaintext)
	if err != nil {
		return nil, fmt.Errorf("frame: encrypt request: %w", err)
	}
	return encrypted, nil
}

// WriteRequest writes a request frame to w.
// If key is nil, the frame is plaintext (useful for dev/debug).
func WriteRequest(w io.Writer, key []byte, seq uint32, r *Request) error {
	data, err := EncodeRequest(key, seq, r)
	if err != nil {
		return err
	}
	_, err = Write(w, seq, data)
	return err
}

// DecryptRequest decrypts a frame (or reads plaintext) and returns the Request.
// If key is nil, frame.Data is treated as plaintext.
func DecryptRequest(key []byte, f *Frame) (*Request, error) {
	var plaintext []byte
	if key == nil {
		plaintext = f.Data
	} else {
		var err error
		plaintext, err = session.Decrypt(key, f.Data)
		if err != nil {
			return nil, fmt.Errorf("frame: decrypt request: %w", err)
		}
	}

	if len(plaintext) < 2 {
		return nil, fmt.Errorf("frame: request too short")
	}

	opcode := binary.BigEndian.Uint16(plaintext[:2])
	r := &Request{Opcode: opcode}

	if len(plaintext) > 2 {
		m, err := tlv.DecodeMap(plaintext[2:])
		if err != nil {
			return nil, fmt.Errorf("frame: decode request tlv: %w", err)
		}
		r.Payload = m
	}

	return r, nil
}

// ReadRequest reads, optionally decrypts, and parses a request frame from r.
func ReadRequest(r io.Reader, key []byte) (*Request, uint32, error) {
	f, err := Read(r)
	if err != nil {
		return nil, 0, err
	}
	req, err := DecryptRequest(key, f)
	if err != nil {
		return nil, 0, err
	}
	return req, f.SequenceNumber, nil
}
