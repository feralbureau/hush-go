// Package tlv implements the Hush Type-Length-Value wire format.
//
// Each value on the wire is:
//
//	type (1 byte) | length (unsigned LEB128 varint) | value (length bytes)
//
// Containers (MAP, ARRAY) are recursive: their value is a sequence of TLV entries.
package tlv

import (
	"io"
)

// Encode writes a TLV value to w.
func Encode(w io.Writer, v Value) (int, error) {
	buf, err := marshalValue(v)
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

// EncodeMap writes a map as a single TLV map value to w.
func EncodeMap(w io.Writer, m *Map) (int, error) {
	return Encode(w, Value{Typ: TypeMap, data: *m})
}

// MustEncode encodes v into a byte slice, panicking on error.
func MustEncode(v Value) []byte {
	buf, err := marshalValue(v)
	if err != nil {
		panic(err)
	}
	return buf
}

// MustEncodeMap encodes a Map into a byte slice.
func MustEncodeMap(m *Map) []byte {
	return MustEncode(Value{Typ: TypeMap, data: *m})
}
