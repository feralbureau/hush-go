package frame

import (
	"bytes"
	"testing"

	"github.com/feralbureau/hush-go/tlv"
)

func TestFrameWriteRead(t *testing.T) {
	var buf bytes.Buffer
	key := make([]byte, 32)

	req := &Request{
		Opcode: 0x0101,
		Payload: tlv.NewMap().
			Set("name", tlv.String("hush")).
			Set("version", tlv.Uint64(1)),
	}

	if err := WriteRequest(&buf, key, 1, req); err != nil {
		t.Fatalf("WriteRequest: %v", err)
	}

	readReq, seq, err := ReadRequest(&buf, key)
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}

	if seq != 1 {
		t.Fatalf("seq: expected 1, got %d", seq)
	}
	if readReq.Opcode != 0x0101 {
		t.Fatalf("opcode: expected 0x0101, got 0x%04x", readReq.Opcode)
	}
	name, ok := readReq.Payload.GetString("name")
	if !ok || name != "hush" {
		t.Fatalf("name: expected 'hush', got '%s'", name)
	}
	ver, ok := readReq.Payload.GetUint64("version")
	if !ok || ver != 1 {
		t.Fatalf("version: expected 1, got %d", ver)
	}
}

func TestResponseWriteRead(t *testing.T) {
	var buf bytes.Buffer
	key := make([]byte, 32)

	resp := &Response{
		Status: StatusSuccess,
		Payload: tlv.NewMap().
			Set("user_id", tlv.Uint64(42)),
	}

	if err := WriteResponse(&buf, key, 1, resp); err != nil {
		t.Fatalf("WriteResponse: %v", err)
	}

	readResp, err := ReadResponse(&buf, key)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}

	if readResp.Status != StatusSuccess {
		t.Fatalf("status: expected success, got %s", readResp.Status)
	}
	uid, ok := readResp.Payload.GetUint64("user_id")
	if !ok || uid != 42 {
		t.Fatalf("user_id: expected 42, got %d", uid)
	}
	if readResp.Seq != 1 {
		t.Fatalf("seq: expected 1, got %d", readResp.Seq)
	}
}

func TestRequestWrongKey(t *testing.T) {
	var buf bytes.Buffer
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key2[0] = 1

	req := &Request{Opcode: 0x0001}
	if err := WriteRequest(&buf, key1, 1, req); err != nil {
		t.Fatal(err)
	}

	_, _, err := ReadRequest(&buf, key2)
	if err == nil {
		t.Fatal("expected error with wrong key")
	}
}

func TestStatusCodes(t *testing.T) {
	codes := []StatusCode{
		StatusSuccess,
		StatusBadRequest,
		StatusUnauthenticated,
		StatusPermissionDenied,
		StatusNotFound,
		StatusSessionExpired,
		StatusRateLimited,
		StatusInternalError,
	}
	for _, c := range codes {
		s := c.String()
		if s == "" {
			t.Fatalf("empty string for code %d", c)
		}
	}
}

func TestEncodeDecodeRequestEmptyPayload(t *testing.T) {
	key := make([]byte, 32)
	data, err := EncodeRequest(key, 1, &Request{Opcode: 0x0001})
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if _, err := Write(&buf, 1, data); err != nil {
		t.Fatal(err)
	}

	f2, err := Read(&buf)
	if err != nil {
		t.Fatal(err)
	}

	req, err := DecryptRequest(key, f2)
	if err != nil {
		t.Fatal(err)
	}
	if req.Opcode != 0x0001 {
		t.Fatalf("expected opcode 0x0001, got 0x%04x", req.Opcode)
	}
	if req.Payload != nil {
		t.Fatal("expected nil payload")
	}
}

func TestFrameTooShort(t *testing.T) {
	// Frame with length=3 (too short for seq).
	buf := bytes.NewBuffer([]byte{0, 0, 0, 3, 1, 2, 3})
	_, err := Read(buf)
	if err == nil {
		t.Fatal("expected error for too-short frame")
	}
}

func TestResponseSeq(t *testing.T) {
	var buf bytes.Buffer
	key := make([]byte, 32)

	resp := &Response{Status: StatusSuccess}
	if err := WriteResponse(&buf, key, 42, resp); err != nil {
		t.Fatal(err)
	}

	readResp, err := ReadResponse(&buf, key)
	if err != nil {
		t.Fatal(err)
	}
	if readResp.Seq != 42 {
		t.Fatalf("expected seq 42, got %d", readResp.Seq)
	}
}
