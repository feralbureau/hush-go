package tlv

import (
	"bytes"
	"testing"
	"time"
	"fmt"
)

func roundtrip(t *testing.T, v Value) {
	t.Helper()
	buf := new(bytes.Buffer)
	n, err := Encode(buf, v)
	if err != nil {
		t.Fatalf("encode %s: %v", v.Typ, err)
	}
	if n != buf.Len() {
		t.Fatalf("encode %s: wrote %d bytes, buffer has %d", v.Typ, n, buf.Len())
	}
	dec, err := Decode(buf)
	if err != nil {
		t.Fatalf("decode %s: %v", v.Typ, err)
	}
	if dec.Typ != v.Typ {
		t.Fatalf("type mismatch: %s vs %s", v.Typ, dec.Typ)
	}
}

func TestString(t *testing.T) {
	v := String("hello hush")
	roundtrip(t, v)
	if v.String() != "hello hush" {
		t.Fatalf("expected 'hello hush', got '%s'", v.String())
	}
}

func TestBytes(t *testing.T) {
	v := Bytes([]byte{0xde, 0xad, 0xbe, 0xef})
	roundtrip(t, v)
	got := v.Bytes()
	if len(got) != 4 || got[0] != 0xde || got[3] != 0xef {
		t.Fatalf("bytes mismatch: %x", got)
	}
}

func TestIntegers(t *testing.T) {
	roundtrip(t, Uint8(255))
	roundtrip(t, Uint16(65535))
	roundtrip(t, Uint32(4294967295))
	roundtrip(t, Uint64(18446744073709551615))
	roundtrip(t, Int32(-2147483648))
	roundtrip(t, Int64(-9223372036854775808))
}

func TestFloats(t *testing.T) {
	roundtrip(t, Float32(3.14159))
	roundtrip(t, Float64(2.718281828459045))
}

func TestBool(t *testing.T) {
	roundtrip(t, Bool(true))
	roundtrip(t, Bool(false))
}

func TestNull(t *testing.T) {
	v := Null()
	roundtrip(t, v)
	if !v.IsNull() {
		t.Fatal("expected null")
	}
}

func TestTimestamp(t *testing.T) {
	now := time.Now().Truncate(time.Millisecond)
	v := Timestamp(now)
	roundtrip(t, v)
	dec := MustDecode(MustEncode(v))
	if !dec.Timestamp().Equal(now) {
		t.Fatalf("timestamp mismatch: %v vs %v", dec.Timestamp(), now)
	}
}

func TestArray(t *testing.T) {
	v := Array([]Value{String("a"), Uint64(42), Bool(true)})
	roundtrip(t, v)
	dec := MustDecode(MustEncode(v))
	arr := dec.Array()
	if len(arr) != 3 {
		t.Fatalf("array length: expected 3, got %d", len(arr))
	}
	if arr[0].String() != "a" {
		t.Fatalf("array[0]: expected 'a', got '%s'", arr[0].String())
	}
	if arr[1].Uint64() != 42 {
		t.Fatalf("array[1]: expected 42, got %d", arr[1].Uint64())
	}
	if !arr[2].Bool() {
		t.Fatal("array[2]: expected true")
	}
}

func TestMap(t *testing.T) {
	m := NewMap()
	m.Set("name", String("hush"))
	m.Set("version", Uint64(1))
	m.Set("active", Bool(true))

	v := Value{Typ: TypeMap, data: *m}
	roundtrip(t, v)

	dec := MustDecode(MustEncode(v))
	dm := dec.Map()

	name, ok := dm.GetString("name")
	if !ok || name != "hush" {
		t.Fatalf("map name: expected 'hush', got '%s' (ok=%v)", name, ok)
	}
	ver, ok := dm.GetUint64("version")
	if !ok || ver != 1 {
		t.Fatalf("map version: expected 1, got %d", ver)
	}
}

func TestNestedMap(t *testing.T) {
	inner := NewMap()
	inner.Set("x", Uint32(100))

	outer := NewMap()
	outer.Set("inner", Value{Typ: TypeMap, data: *inner})
	outer.Set("label", String("nested"))

	v := Value{Typ: TypeMap, data: *outer}
	roundtrip(t, v)

	dec := MustDecode(MustEncode(v))
	m := dec.Map()

	innerDec, ok := m.GetMap("inner")
	if !ok {
		t.Fatal("expected inner map")
	}
	xV, ok := innerDec.Get("x")
	if !ok || xV.Typ != TypeUint32 {
		t.Fatal("inner.x: expected uint32")
	}
	if xV.Uint32() != 100 {
		t.Fatalf("inner.x: expected 100, got %d", xV.Uint32())
	}
}

func TestEmptyPayload(t *testing.T) {
	m := NewMap()
	v := Value{Typ: TypeMap, data: *m}
	roundtrip(t, v)
}

func TestLargeString(t *testing.T) {
	s := string(make([]byte, 10000))
	v := String(s)
	roundtrip(t, v)
}

func TestDecodeMap(t *testing.T) {
	m := NewMap()
	m.Set("key", String("val"))
	buf := MustEncodeMap(m)

	dec, err := DecodeMap(buf)
	if err != nil {
		t.Fatalf("DecodeMap: %v", err)
	}
	v, ok := dec.GetString("key")
	if !ok || v != "val" {
		t.Fatalf("DecodeMap: expected 'val', got '%s'", v)
	}
}

func TestDecodeBytes(t *testing.T) {
	buf := MustEncode(Uint64(42))
	v, err := DecodeBytes(buf)
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	if v.Uint64() != 42 {
		t.Fatalf("expected 42, got %d", v.Uint64())
	}
}

func TestMapCloneIsolation(t *testing.T) {
	original := NewMap()
	original.Set("key", String("original"))

	cloned := original.Clone()
	cloned.Set("key", String("mutated"))

	val, _ := original.GetString("key")
	if val != "original" {
		t.Fatal("Clone() should not share state: expected 'original'")
	}
}

func TestMapGetMapIsolation(t *testing.T) {
	inner := NewMap()
	inner.Set("val", String("original"))

	outer := NewMap()
	outer.Set("inner", Value{Typ: TypeMap, data: *inner})

	got, ok := outer.GetMap("inner")
	if !ok {
		t.Fatal("expected inner map")
	}
	got.Set("val", String("mutated"))

	check, _ := outer.GetMap("inner")
	val, _ := check.GetString("val")
	if val != "original" {
		t.Fatal("GetMap should return a copy: expected 'original'")
	}
}

func TestMapIterDoesntEscapeData(t *testing.T) {
	m := NewMap()
	m.Set("a", String("1"))
	m.Set("b", String("2"))

	var seen int
	m.Iter(func(key string, val Value) bool {
		seen++
		return true
	})
	if seen != 2 {
		t.Fatalf("expected 2 iterations, got %d", seen)
	}
}

func TestDecodeOversizeVarint(t *testing.T) {
	// Crafted payload with a huge varint length
	buf := []byte{byte(TypeString), 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 'h', 'i'}
	_, err := DecodeBytes(buf)
	if err == nil {
		t.Fatal("expected error for oversize varint")
	}
}

func TestDecodeNestedTooDeep(t *testing.T) {
	// Build deeply nested arrays — 1000 levels deep, should fail
	v := Null()
	for i := 0; i < 1000; i++ {
		v = Array([]Value{v})
	}
	encoded := MustEncode(v)
	_, err := DecodeBytes(encoded)
	if err == nil {
		t.Fatal("expected error for deeply nested value (1000 levels, max 64)")
	}
	t.Logf("deeply nested correctly rejected: %v", err)
}

func TestDecodeMaxDepth(t *testing.T) {
	// Build nested arrays exactly at the limit — should succeed
	v := Uint64(1)
	for i := 0; i < MaxDecodeDepth; i++ {
		v = Array([]Value{v})
	}
	encoded := MustEncode(v)
	decoded, err := DecodeBytes(encoded)
	if err != nil {
		t.Fatalf("exact max depth (%d) should succeed: %v", MaxDecodeDepth, err)
	}
	_ = decoded
}

func TestDecodeOneOverMaxDepth(t *testing.T) {
	// One level over the limit — should fail
	v := Uint64(1)
	for i := 0; i < MaxDecodeDepth+1; i++ {
		v = Array([]Value{v})
	}
	encoded := MustEncode(v)
	_, err := DecodeBytes(encoded)
	if err == nil {
		t.Fatalf("expected error for %d levels (max %d)", MaxDecodeDepth+1, MaxDecodeDepth)
	}
}

func TestMaxUint64(t *testing.T) {
	v := Uint64(^uint64(0))
	buf := MustEncode(v)
	v2, err := DecodeBytes(buf)
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	if v2.Uint64() != ^uint64(0) {
		t.Fatalf("expected max uint64, got %d", v2.Uint64())
	}
}

func TestMixedArray(t *testing.T) {
	arr := Array([]Value{
		String("hello"),
		Uint64(42),
		Bool(true),
		Null(),
	})
	buf := MustEncode(arr)
	v, err := DecodeBytes(buf)
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	vals := v.Array()
	if len(vals) != 4 {
		t.Fatalf("expected 4 elements, got %d", len(vals))
	}
	if vals[0].String() != "hello" {
		t.Fatal("first element should be 'hello'")
	}
	if vals[1].Uint64() != 42 {
		t.Fatal("second element should be 42")
	}
	if !vals[2].Bool() {
		t.Fatal("third element should be true")
	}
	if vals[3].Typ != TypeNull {
		t.Fatal("fourth element should be null")
	}
}

func TestNestedArray(t *testing.T) {
	inner := Array([]Value{Uint64(1), Uint64(2)})
	outer := Array([]Value{inner, Uint64(3)})

	buf := MustEncode(outer)
	v, err := DecodeBytes(buf)
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}

	outerArr := v.Array()
	if len(outerArr) != 2 {
		t.Fatalf("expected 2 outer elements, got %d", len(outerArr))
	}

	innerArr := outerArr[0].Array()
	if len(innerArr) != 2 {
		t.Fatalf("expected 2 inner elements, got %d", len(innerArr))
	}
	if innerArr[0].Uint64() != 1 || innerArr[1].Uint64() != 2 {
		t.Fatal("inner array values wrong")
	}
	if outerArr[1].Uint64() != 3 {
		t.Fatal("outer second value wrong")
	}
}

func TestDeeplyNestedMap(t *testing.T) {
	m := NewMap()
	inner := NewMap().Set("a", Uint64(1)).Set("b", String("deep"))
	m.Set("outer", Value{Typ: TypeMap, data: *inner})
	m.Set("sibling", Uint64(2))

	buf := MustEncodeMap(m)
	decoded, err := DecodeMap(buf)
	if err != nil {
		t.Fatalf("DecodeMap: %v", err)
	}

	outerV, ok := decoded.Get("outer")
	if !ok || outerV.Typ != TypeMap {
		t.Fatal("expected outer map")
	}

	innerM := outerV.Map()
	a, _ := innerM.GetUint64("a")
	b, _ := innerM.GetString("b")
	if a != 1 || b != "deep" {
		t.Fatal("inner map values wrong")
	}

	sib, _ := decoded.GetUint64("sibling")
	if sib != 2 {
		t.Fatal("sibling value wrong")
	}
}

func TestEncodeDecodeBytes(t *testing.T) {
	data := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE}
	v := Bytes(data)
	buf := MustEncode(v)
	v2, err := DecodeBytes(buf)
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	result := v2.Bytes()
	if len(result) != len(data) {
		t.Fatalf("len mismatch: %d vs %d", len(result), len(data))
	}
	for i := range data {
		if result[i] != data[i] {
			t.Fatalf("byte %d mismatch", i)
		}
	}
}

func TestLargeMap(t *testing.T) {
	m := NewMap()
	for i := 0; i < 100; i++ {
		m.Set(fmt.Sprintf("key_%d", i), Uint64(uint64(i)))
	}

	buf := MustEncodeMap(m)
	decoded, err := DecodeMap(buf)
	if err != nil {
		t.Fatalf("DecodeMap: %v", err)
	}

	for i := 0; i < 100; i++ {
		v, ok := decoded.GetUint64(fmt.Sprintf("key_%d", i))
		if !ok || v != uint64(i) {
			t.Fatalf("key_%d: expected %d, got %d (ok=%v)", i, i, v, ok)
		}
	}
}

func TestEncodeDecodeAll(t *testing.T) {
	buf := new(bytes.Buffer)
	Encode(buf, String("a"))
	Encode(buf, Uint64(2))
	Encode(buf, Bool(true))

	vals, err := DecodeAll(buf)
	if err != nil {
		t.Fatalf("DecodeAll: %v", err)
	}
	if len(vals) != 3 {
		t.Fatalf("expected 3 values, got %d", len(vals))
	}
	if vals[0].String() != "a" || vals[1].Uint64() != 2 || !vals[2].Bool() {
		t.Fatal("values mismatch")
	}
}

func TestDecodeAllEmpty(t *testing.T) {
	buf := new(bytes.Buffer)
	vals, err := DecodeAll(buf)
	if err != nil {
		t.Fatalf("DecodeAll: %v", err)
	}
	if len(vals) != 0 {
		t.Fatalf("expected 0 values, got %d", len(vals))
	}
}

func TestDecodeTruncated(t *testing.T) {
	// A uint16 value needs 2 bytes, only provide 1
	_, err := DecodeBytes([]byte{byte(TypeUint16), 2, 0x01})
	if err == nil {
		t.Fatal("expected error for truncated data")
	}
}

func TestDecodeInvalidType(t *testing.T) {
	_, err := DecodeBytes([]byte{0xFF, 0x00})
	if err == nil {
		t.Fatal("expected error for unknown type")
	}
}

func TestDecodeOversizedPayload(t *testing.T) {
	// A size that exceeds our max limit
	_, err := DecodeBytes([]byte{byte(TypeBytes), 0x80, 0x80, 0x80, 0x80, 0x08})
	if err == nil {
		t.Fatal("expected error for oversized payload")
	}
}

func TestMapGetBytes(t *testing.T) {
	m := NewMap().Set("data", Bytes([]byte{1, 2, 3}))
	v, ok := m.GetBytes("data")
	if !ok || len(v) != 3 || v[0] != 1 || v[1] != 2 || v[2] != 3 {
		t.Fatal("GetBytes failed")
	}

	_, ok = m.GetBytes("nonexistent")
	if ok {
		t.Fatal("GetBytes should return false for nonexistent key")
	}
}

func TestMapIter(t *testing.T) {
	m := NewMap()
	m.Set("a", Uint64(1))
	m.Set("b", Uint64(2))
	m.Set("c", Uint64(3))

	var keys []string
	m.Iter(func(key string, val Value) bool {
		keys = append(keys, key)
		return true
	})
	if len(keys) != 3 || keys[0] != "a" || keys[1] != "b" || keys[2] != "c" {
		t.Fatalf("Iter gave wrong order: %v", keys)
	}

	// Test early stop
	keys = nil
	m.Iter(func(key string, val Value) bool {
		keys = append(keys, key)
		return false
	})
	if len(keys) != 1 || keys[0] != "a" {
		t.Fatalf("Iter early stop gave: %v", keys)
	}
}

func TestMapOverwrite(t *testing.T) {
	m := NewMap()
	m.Set("key", Uint64(1))
	m.Set("key", Uint64(2))

	v, ok := m.GetUint64("key")
	if !ok || v != 2 {
		t.Fatalf("expected overwritten value 2, got %d (ok=%v)", v, ok)
	}

	if len(m.entries) != 1 {
		t.Fatalf("expected 1 entry after overwrite, got %d", len(m.entries))
	}
}

func TestTimestampRoundtrip(t *testing.T) {
	now := time.Now()
	v := Timestamp(now)
	buf := MustEncode(v)
	v2, err := DecodeBytes(buf)
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	decoded := v2.Timestamp()
	// Millisecond precision
	expectedMs := now.UnixMilli()
	gotMs := decoded.UnixMilli()
	if expectedMs != gotMs {
		t.Fatalf("timestamp mismatch: %d vs %d", expectedMs, gotMs)
	}
}

func TestFloat32Roundtrip(t *testing.T) {
	v := Float32(3.14159)
	buf := MustEncode(v)
	v2, err := DecodeBytes(buf)
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	if v2.Float32() != 3.14159 {
		t.Fatalf("float32 mismatch: %f", v2.Float32())
	}
}

func TestInt32Roundtrip(t *testing.T) {
	v := Int32(-42)
	buf := MustEncode(v)
	v2, err := DecodeBytes(buf)
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	if v2.Int32() != -42 {
		t.Fatalf("int32 mismatch: %d", v2.Int32())
	}
}

func TestInt64Roundtrip(t *testing.T) {
	v := Int64(-1 << 62)
	buf := MustEncode(v)
	v2, err := DecodeBytes(buf)
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	if v2.Int64() != -1<<62 {
		t.Fatalf("int64 mismatch: %d", v2.Int64())
	}
}

func TestNegativeFloat64(t *testing.T) {
	v := Float64(-273.15)
	buf := MustEncode(v)
	v2, err := DecodeBytes(buf)
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	if v2.Float64() != -273.15 {
		t.Fatalf("float64 mismatch: %f", v2.Float64())
	}
}
