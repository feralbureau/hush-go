// Package frame implements the Hush encrypted frame wire format.
//
// Wire format (stream):
//
//	frame_length (4 bytes big-endian) || frame_data
//
// Encrypted frame_data:
//
//	sequence_number (4 bytes big-endian) || nonce (12 bytes) || ciphertext || AEAD tag (16 bytes)
//
// Plaintext frame_data (no encryption):
//
//	sequence_number (4 bytes big-endian) || plaintext
package frame

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// MaxFrameSize is the maximum allowed frame payload length (1 MiB).
	MaxFrameSize = 1 << 20

	// FrameOverhead is the minimum encrypted frame data: seq(4) + nonce(12) + tag(16).
	FrameOverhead = 4 + 12 + 16

	// FrameMinData is the minimum frame data size without encryption (just the sequence number).
	FrameMinData = 4
)

// Frame is a single protocol frame.
type Frame struct {
	SequenceNumber uint32
	// Data contains the frame payload.
	// When encrypted: nonce (12) || ciphertext || tag (16)
	// When plaintext: plaintext bytes
	Data []byte
}

var ErrFrameTooLarge = fmt.Errorf("frame: payload exceeds max size (%d bytes)", MaxFrameSize)
var ErrFrameTooShort = fmt.Errorf("frame: payload too short (min %d bytes)", FrameMinData)

// Read reads and parses a single length-prefixed frame from r.
func Read(r io.Reader) (*Frame, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, fmt.Errorf("frame: read length: %w", err)
	}
	frameLen := binary.BigEndian.Uint32(lenBuf)

	if frameLen > MaxFrameSize {
		return nil, fmt.Errorf("frame: too large (%d bytes, max %d): %w", frameLen, MaxFrameSize, ErrFrameTooLarge)
	}

	if frameLen < FrameMinData {
		return nil, fmt.Errorf("frame: too short (%d bytes): %w", frameLen, ErrFrameTooShort)
	}

	data := make([]byte, frameLen)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, fmt.Errorf("frame: read payload: %w", err)
	}

	seq := binary.BigEndian.Uint32(data[:4])
	return &Frame{
		SequenceNumber: seq,
		Data:           data[4:],
	}, nil
}

// Write writes a length-prefixed frame to w.
func Write(w io.Writer, seq uint32, frameData []byte) (int, error) {
	totalLen := 4 + len(frameData) // seq + rest
	if totalLen > MaxFrameSize {
		return 0, fmt.Errorf("frame: write size exceeds max (%d bytes): %w", totalLen, ErrFrameTooLarge)
	}

	buf := make([]byte, 4+totalLen)
	binary.BigEndian.PutUint32(buf[:4], uint32(totalLen))
	binary.BigEndian.PutUint32(buf[4:8], seq)
	copy(buf[8:], frameData)

	return w.Write(buf)
}

// ReadFrameLen reads only the frame length header.
func ReadFrameLen(r io.Reader) (uint32, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return 0, fmt.Errorf("frame: read length: %w", err)
	}
	return binary.BigEndian.Uint32(lenBuf), nil
}

// MaxSafePayload returns the maximum plaintext size that fits in an encrypted frame.
func MaxSafePayload() int {
	return MaxFrameSize - FrameOverhead
}

// WireOverhead returns total wire bytes added to plaintext in encrypted mode.
func WireOverhead() int { return 36 }

func (f *Frame) String() string {
	return fmt.Sprintf("Frame{seq=%d, data=%d bytes}", f.SequenceNumber, len(f.Data))
}
