package tlv

import (
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

// Type is a TLV type code.
type Type byte

const (
	TypeString    Type = 0x01
	TypeBytes     Type = 0x02
	TypeUint8     Type = 0x03
	TypeUint16    Type = 0x04
	TypeUint32    Type = 0x05
	TypeUint64    Type = 0x06
	TypeInt32     Type = 0x07
	TypeInt64     Type = 0x08
	TypeFloat32   Type = 0x09
	TypeFloat64   Type = 0x0A
	TypeBool      Type = 0x0B
	TypeArray     Type = 0x0C
	TypeMap       Type = 0x0D
	TypeNull      Type = 0x0E
	TypeTimestamp Type = 0x0F
)

func (t Type) String() string {
	switch t {
	case TypeString:
		return "string"
	case TypeBytes:
		return "bytes"
	case TypeUint8:
		return "uint8"
	case TypeUint16:
		return "uint16"
	case TypeUint32:
		return "uint32"
	case TypeUint64:
		return "uint64"
	case TypeInt32:
		return "int32"
	case TypeInt64:
		return "int64"
	case TypeFloat32:
		return "float32"
	case TypeFloat64:
		return "float64"
	case TypeBool:
		return "bool"
	case TypeArray:
		return "array"
	case TypeMap:
		return "map"
	case TypeNull:
		return "null"
	case TypeTimestamp:
		return "timestamp"
	default:
		return fmt.Sprintf("unknown(0x%02x)", byte(t))
	}
}

// Value is a dynamically-typed TLV value.
type Value struct {
	Typ  Type
	data interface{}
}

// String returns a string value. Panics if the type is not TypeString.
func (v Value) String() string { return v.data.(string) }

// Bytes returns a byte slice value. Panics if the type is not TypeBytes.
func (v Value) Bytes() []byte { return v.data.([]byte) }

func (v Value) Uint8() uint8     { return v.data.(uint8) }
func (v Value) Uint16() uint16   { return v.data.(uint16) }
func (v Value) Uint32() uint32   { return v.data.(uint32) }
func (v Value) Uint64() uint64   { return v.data.(uint64) }
func (v Value) Int32() int32     { return v.data.(int32) }
func (v Value) Int64() int64     { return v.data.(int64) }
func (v Value) Float32() float32 { return v.data.(float32) }
func (v Value) Float64() float64 { return v.data.(float64) }
func (v Value) Bool() bool       { return v.data.(bool) }

// Array returns the element slice.
func (v Value) Array() []Value { return v.data.([]Value) }

// Map returns a copy of the map entries. The caller can safely iterate the copy.
func (v Value) Map() Map {
	//  Return a copy to prevent the caller from mutating the original entries slice.
	m := v.data.(Map)
	return Map{entries: append([]MapEntry(nil), m.entries...)}
}

func (v Value) Timestamp() time.Time { return v.data.(time.Time) }

// IsNull reports whether the value is the null sentinel.
func (v Value) IsNull() bool { return v.Typ == TypeNull }

// --- Value constructors ---

func String(s string) Value { return Value{Typ: TypeString, data: s} }

//	Bytes creates a TLV binary value.
//
// The byte slice is stored by reference — the caller must not modify it after calling this.
func Bytes(b []byte) Value { return Value{Typ: TypeBytes, data: b} }

// Uint8 creates a TLV uint8 value.
func Uint8(n uint8) Value { return Value{Typ: TypeUint8, data: n} }

// Uint16 creates a TLV uint16 value (big-endian wire format).
func Uint16(n uint16) Value { return Value{Typ: TypeUint16, data: n} }

// Uint32 creates a TLV uint32 value (big-endian wire format).
func Uint32(n uint32) Value { return Value{Typ: TypeUint32, data: n} }

// Uint64 creates a TLV uint64 value (big-endian wire format).
func Uint64(n uint64) Value { return Value{Typ: TypeUint64, data: n} }

// Int32 creates a TLV int32 value (big-endian two's complement wire format).
func Int32(n int32) Value { return Value{Typ: TypeInt32, data: n} }

// Int64 creates a TLV int64 value (big-endian two's complement wire format).
func Int64(n int64) Value { return Value{Typ: TypeInt64, data: n} }

// Float32 creates a TLV float32 value (IEEE 754 big-endian wire format).
func Float32(f float32) Value { return Value{Typ: TypeFloat32, data: f} }

// Float64 creates a TLV float64 value (IEEE 754 big-endian wire format).
func Float64(f float64) Value { return Value{Typ: TypeFloat64, data: f} }

// Bool creates a TLV boolean value.
func Bool(b bool) Value { return Value{Typ: TypeBool, data: b} }

// Array creates a TLV array value containing the given elements.
func Array(vs []Value) Value { return Value{Typ: TypeArray, data: vs} }

// Null creates a TLV null sentinel value.
func Null() Value { return Value{Typ: TypeNull} }

// Timestamp creates a TLV timestamp value (Unix milliseconds, int64, big-endian wire format).
func Timestamp(t time.Time) Value { return Value{Typ: TypeTimestamp, data: t} }

// Map is an ordered map of string-keyed TLV values.
type Map struct {
	entries []MapEntry
}

type MapEntry struct {
	Key   string
	Value Value
}

// NewMap creates a new empty ordered string-keyed map.
func NewMap() *Map { return &Map{} }

func (m *Map) Set(key string, v Value) *Map {
	for i := range m.entries {
		if m.entries[i].Key == key {
			m.entries[i].Value = v
			return m
		}
	}
	m.entries = append(m.entries, MapEntry{Key: key, Value: v})
	return m
}

func (m *Map) Get(key string) (Value, bool) {
	for _, e := range m.entries {
		if e.Key == key {
			return e.Value, true
		}
	}
	return Value{}, false
}

func (m *Map) GetString(key string) (string, bool) {
	v, ok := m.Get(key)
	if !ok || v.Typ != TypeString {
		return "", false
	}
	return v.String(), true
}

func (m *Map) GetUint64(key string) (uint64, bool) {
	v, ok := m.Get(key)
	if !ok || v.Typ != TypeUint64 {
		return 0, false
	}
	return v.Uint64(), true
}

func (m *Map) GetBytes(key string) ([]byte, bool) {
	v, ok := m.Get(key)
	if !ok || v.Typ != TypeBytes {
		return nil, false
	}
	return v.Bytes(), true
}

func (m *Map) GetMap(key string) (*Map, bool) {
	v, ok := m.Get(key)
	if !ok || v.Typ != TypeMap {
		return nil, false
	}
	original := v.data.(Map)
	//  Return a copy so the caller can't mutate the original.
	copied := Map{entries: append([]MapEntry(nil), original.entries...)}
	return &copied, true
}

func (m *Map) Iter(f func(key string, val Value) bool) {
	for _, e := range m.entries {
		if !f(e.Key, e.Value) {
			break
		}
	}
}

// Clone returns a deep copy of the map.
func (m *Map) Clone() *Map {
	c := &Map{entries: make([]MapEntry, len(m.entries))}
	for i, e := range m.entries {
		c.entries[i] = MapEntry{Key: e.Key, Value: e.Value}
	}
	return c
}

// MapValue wraps a Map into a Value for use in nested containers.
func MapValue(m *Map) Value {
	return Value{Typ: TypeMap, data: *m}
}

// --- internal encoding helpers ---

// marshalPayload returns the raw value bytes (without type tag or length prefix).
func marshalPayload(v Value) ([]byte, error) {
	switch v.Typ {
	case TypeString:
		return []byte(v.String()), nil
	case TypeBytes:
		return v.Bytes(), nil
	case TypeUint8:
		return []byte{v.Uint8()}, nil
	case TypeUint16:
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, v.Uint16())
		return b, nil
	case TypeUint32:
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, v.Uint32())
		return b, nil
	case TypeUint64:
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, v.Uint64())
		return b, nil
	case TypeInt32:
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(v.Int32()))
		return b, nil
	case TypeInt64:
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(v.Int64()))
		return b, nil
	case TypeFloat32:
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, math.Float32bits(v.Float32()))
		return b, nil
	case TypeFloat64:
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, math.Float64bits(v.Float64()))
		return b, nil
	case TypeBool:
		if v.Bool() {
			return []byte{1}, nil
		}
		return []byte{0}, nil
	case TypeNull:
		return nil, nil
	case TypeTimestamp:
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(v.Timestamp().UnixMilli()))
		return b, nil
	case TypeArray:
		var buf []byte
		for _, elem := range v.Array() {
			elemBuf, err := marshalValue(elem)
			if err != nil {
				return nil, err
			}
			buf = append(buf, elemBuf...)
		}
		return buf, nil
	case TypeMap:
		var buf []byte
		m := v.data.(Map)
		for _, entry := range m.entries {
			keyBuf, err := marshalValue(String(entry.Key))
			if err != nil {
				return nil, err
			}
			buf = append(buf, keyBuf...)
			valBuf, err := marshalValue(entry.Value)
			if err != nil {
				return nil, err
			}
			buf = append(buf, valBuf...)
		}
		return buf, nil
	default:
		return nil, fmt.Errorf("tlv: unknown type 0x%02x", byte(v.Typ))
	}
}

// marshalValue returns the full TLV encoding (type + length + value).
func marshalValue(v Value) ([]byte, error) {
	payload, err := marshalPayload(v)
	if err != nil {
		return nil, err
	}
	varintBuf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(varintBuf, uint64(len(payload)))
	out := make([]byte, 0, 1+n+len(payload))
	out = append(out, byte(v.Typ))
	out = append(out, varintBuf[:n]...)
	out = append(out, payload...)
	return out, nil
}
