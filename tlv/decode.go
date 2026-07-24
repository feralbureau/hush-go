package tlv

import (
	"errors"
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"time"
)

// MaxDecodeDepth is the maximum nesting depth for composite types (arrays, maps).
const MaxDecodeDepth = 64

// Decode reads and parses a single TLV value from r.
func Decode(r io.Reader) (Value, error) {
	br := bufio.NewReader(r)
	return decodeReader(br)
}

// decodeReader reads a single TLV value using a bufio.Reader (which implements io.ByteReader).
func decodeReader(br *bufio.Reader) (Value, error) {
	typ, err := br.ReadByte()
	if err != nil {
		return Value{}, fmt.Errorf("tlv: read type: %w", err)
	}
	t := Type(typ)

	length, err := binary.ReadUvarint(br)
	if length > 524288 {
		return Value{}, fmt.Errorf("tlv: payload too large (%d bytes, max 524288)", length)
	}
	if err != nil {
		return Value{}, fmt.Errorf("tlv: read length: %w", err)
	}

	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(br, payload); err != nil {
			return Value{}, fmt.Errorf("tlv: read payload: %w", err)
		}
	}

	return decodeValue(t, payload, 0)
}

// DecodeAll reads all TLV values from r until EOF.
func DecodeAll(r io.Reader) ([]Value, error) {
	br := bufio.NewReader(r)
	var vals []Value
	for {
		v, err := decodeReader(br)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		vals = append(vals, v)
	}
	return vals, nil
}

// MustDecode decodes a single TLV value from a byte slice, panicking on error.
func MustDecode(buf []byte) Value {
	v, err := DecodeBytes(buf)
	if err != nil {
		panic(err)
	}
	return v
}

// DecodeBytes decodes a single TLV value from a byte slice.
func DecodeBytes(buf []byte) (Value, error) {
	if len(buf) < 1 {
		return Value{}, io.ErrUnexpectedEOF
	}
	t := Type(buf[0])
	length, n := binary.Uvarint(buf[1:])
	if n <= 0 {
		return Value{}, fmt.Errorf("tlv: invalid varint length")
	}
	payloadStart := 1 + uint64(n)
	if uint64(len(buf)) < payloadStart+length {
		return Value{}, io.ErrUnexpectedEOF
	}
	return decodeValue(t, buf[payloadStart:payloadStart+length], 0)
}

func decodeValue(t Type, payload []byte, depth int) (Value, error) {
	if depth > MaxDecodeDepth {
		return Value{}, fmt.Errorf("tlv: nested depth %d exceeds maximum %d", depth, MaxDecodeDepth)
	}
	switch t {
	case TypeString:
		return String(string(payload)), nil
	case TypeBytes:
		b := make([]byte, len(payload))
		copy(b, payload)
		return Bytes(b), nil
	case TypeUint8:
		if len(payload) < 1 {
			return Value{}, fmt.Errorf("tlv: uint8 needs 1 byte")
		}
		return Uint8(payload[0]), nil
	case TypeUint16:
		if len(payload) < 2 {
			return Value{}, fmt.Errorf("tlv: uint16 needs 2 bytes")
		}
		return Uint16(binary.BigEndian.Uint16(payload[:2])), nil
	case TypeUint32:
		if len(payload) < 4 {
			return Value{}, fmt.Errorf("tlv: uint32 needs 4 bytes")
		}
		return Uint32(binary.BigEndian.Uint32(payload[:4])), nil
	case TypeUint64:
		if len(payload) < 8 {
			return Value{}, fmt.Errorf("tlv: uint64 needs 8 bytes")
		}
		return Uint64(binary.BigEndian.Uint64(payload[:8])), nil
	case TypeInt32:
		if len(payload) < 4 {
			return Value{}, fmt.Errorf("tlv: int32 needs 4 bytes")
		}
		return Int32(int32(binary.BigEndian.Uint32(payload[:4]))), nil
	case TypeInt64:
		if len(payload) < 8 {
			return Value{}, fmt.Errorf("tlv: int64 needs 8 bytes")
		}
		return Int64(int64(binary.BigEndian.Uint64(payload[:8]))), nil
	case TypeFloat32:
		if len(payload) < 4 {
			return Value{}, fmt.Errorf("tlv: float32 needs 4 bytes")
		}
		return Float32(math.Float32frombits(binary.BigEndian.Uint32(payload[:4]))), nil
	case TypeFloat64:
		if len(payload) < 8 {
			return Value{}, fmt.Errorf("tlv: float64 needs 8 bytes")
		}
		return Float64(math.Float64frombits(binary.BigEndian.Uint64(payload[:8]))), nil
	case TypeBool:
		if len(payload) < 1 {
			return Value{}, fmt.Errorf("tlv: bool needs 1 byte")
		}
		return Bool(payload[0] != 0), nil
	case TypeNull:
		return Null(), nil
	case TypeTimestamp:
		if len(payload) < 8 {
			return Value{}, fmt.Errorf("tlv: timestamp needs 8 bytes")
		}
		ms := binary.BigEndian.Uint64(payload[:8])
		return Timestamp(time.UnixMilli(int64(ms))), nil
	case TypeArray:
		var elems []Value
		buf := payload
		for len(buf) > 0 {
			v, n, err := decodeValueBytes(buf, depth)
			if err != nil {
				return Value{}, err
			}
			elems = append(elems, v)
			buf = buf[n:]
		}
		return Array(elems), nil
	case TypeMap:
		m := NewMap()
		buf := payload
		for len(buf) > 0 {
			key, n, err := decodeValueBytes(buf, depth+1)
			if err != nil {
				return Value{}, err
			}
			if key.Typ != TypeString {
				return Value{}, fmt.Errorf("tlv: map key must be string, got %s", key.Typ)
			}
			buf = buf[n:]
			if len(buf) == 0 {
				return Value{}, fmt.Errorf("tlv: map entry missing value for key %q", key.String())
			}
			val, n2, err := decodeValueBytes(buf, depth+1)
			if err != nil {
				return Value{}, err
			}
			buf = buf[n2:]
			m.Set(key.String(), val)
		}
		return Value{Typ: TypeMap, data: *m}, nil
	default:
		return Value{}, fmt.Errorf("tlv: unknown type 0x%02x", byte(t))
	}
}

// decodeValueBytes decodes a single TLV value from the beginning of buf
// and returns the value plus the number of bytes consumed.
func decodeValueBytes(buf []byte, depth int) (Value, int, error) {
	if len(buf) < 1 {
		return Value{}, 0, io.ErrUnexpectedEOF
	}
	t := Type(buf[0])
	length, n := binary.Uvarint(buf[1:])
	if length > 524288 {
		return Value{}, 0, fmt.Errorf("tlv: payload too large (%d bytes, max 524288)", length)
	}
	if n <= 0 {
		return Value{}, 0, fmt.Errorf("tlv: invalid varint length")
	}
	start := uint64(1 + n)
	if uint64(len(buf)) < start+length {
		return Value{}, 0, io.ErrUnexpectedEOF
	}
	v, err := decodeValue(t, buf[int(start):int(start+length)], depth+1)
	if err != nil {
		return Value{}, 0, err
	}
	return v, int(start + length), nil
}

// DecodeMap reads a single TLV map value from a byte slice.
func DecodeMap(buf []byte) (*Map, error) {
	v, err := DecodeBytes(buf)
	if err != nil {
		return nil, err
	}
	if v.Typ != TypeMap {
		return nil, fmt.Errorf("tlv: expected map, got %s", v.Typ)
	}
	m := v.data.(Map)
	return &m, nil
}
