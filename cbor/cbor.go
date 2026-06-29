// Package cbor implements canonical CBOR encoding and decoding per RFC 8949
// Section 4.2.3 (length-first deterministic encoding) as required by
// AAFP RFC-0002 Section 8.
//
// This implementation is written from the AAFP RFC specification alone.
// It supports the subset of CBOR needed by AAFP:
//   - Unsigned integers (major type 0)
//   - Negative integers (major type 1)
//   - Byte strings (major type 2)
//   - Text strings (major type 3)
//   - Arrays (major type 4)
//   - Maps (major type 5) with both integer and string keys
//   - Simple values: false, true, null (major type 7)
//
// Canonical encoding rules (RFC-0002 §8.1):
//   1. Integers use shortest encoding
//   2. Map keys sorted length-first (shorter keys before longer,
//      within same length, bytewise lexicographic)
//   3. No indefinite-length
//   4. No tags (major type 6)
//   5. No floating point (not used in AAFP v1)
package cbor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

// CBOR major types
const (
	mtUnsigned = 0x00
	mtNegative = 0x20
	mtByteStr  = 0x40
	mtTextStr  = 0x60
	mtArray    = 0x80
	mtMap      = 0xa0
	mtSimple   = 0xe0
)

// Additional info values
const (
	aiOneByte    = 24
	aiTwoBytes   = 25
	aiFourBytes  = 26
	aiEightBytes = 27
	aiBreak      = 31
)

// Simple values
const (
	simpleFalse    = 20
	simpleTrue     = 21
	simpleNull     = 22
	simpleUndef    = 23
)

// Value represents a decoded CBOR value.
type Value struct {
	kind   ValueKind
	uint   uint64
	neg    int64
	bytes  []byte
	str    string
	arr    []Value
	intMap []IntMapEntry
	strMap []StrMapEntry
	bool   bool
}

type ValueKind int

const (
	KindUnsigned ValueKind = iota
	KindNegative
	KindByteString
	KindTextString
	KindArray
	KindIntMap
	KindStrMap
	KindBool
	KindNull
)

// IntMapEntry is a single integer-keyed map entry.
type IntMapEntry struct {
	Key   int64
	Value Value
}

// StrMapEntry is a single string-keyed map entry.
type StrMapEntry struct {
	Key   string
	Value Value
}

// Constructors return Value (not pointer) for convenience.

func UUint(n uint64) Value {
	return Value{kind: KindUnsigned, uint: n}
}

func NInt(n int64) Value {
	if n >= 0 {
		return Value{kind: KindUnsigned, uint: uint64(n)}
	}
	return Value{kind: KindNegative, neg: n}
}

func BStr(b []byte) Value {
	return Value{kind: KindByteString, bytes: b}
}

func TStr(s string) Value {
	return Value{kind: KindTextString, str: s}
}

func Arr(items []Value) Value {
	return Value{kind: KindArray, arr: items}
}

func IMap(entries []IntMapEntry) Value {
	return Value{kind: KindIntMap, intMap: entries}
}

func SMap(entries []StrMapEntry) Value {
	return Value{kind: KindStrMap, strMap: entries}
}

func Bool(b bool) Value {
	return Value{kind: KindBool, bool: b}
}

func Null() Value {
	return Value{kind: KindNull}
}

// Accessors

func (v *Value) Kind() ValueKind    { return v.kind }
func (v *Value) Uint() uint64       { return v.uint }
func (v *Value) Neg() int64         { return v.neg }
func (v *Value) Int() int64 {
	if v.kind == KindUnsigned {
		return int64(v.uint)
	}
	return v.neg
}
func (v *Value) Bytes() []byte       { return v.bytes }
func (v *Value) Str() string         { return v.str }
func (v *Value) Arr() []Value        { return v.arr }
func (v *Value) IntMap() []IntMapEntry { return v.intMap }
func (v *Value) StrMap() []StrMapEntry { return v.strMap }
func (v *Value) BoolVal() bool       { return v.bool }

// IntMapGet returns the value for a given integer key, or nil if not found.
func (v *Value) IntMapGet(key int64) *Value {
	for i := range v.intMap {
		if v.intMap[i].Key == key {
			return &v.intMap[i].Value
		}
	}
	return nil
}

// StrMapGet returns the value for a given string key, or nil if not found.
func (v *Value) StrMapGet(key string) *Value {
	for i := range v.strMap {
		if v.strMap[i].Key == key {
			return &v.strMap[i].Value
		}
	}
	return nil
}

// Encode encodes a Value to canonical CBOR bytes.
func Encode(v *Value) ([]byte, error) {
	var buf bytes.Buffer
	if err := encodeValue(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encodeValue(buf *bytes.Buffer, v *Value) error {
	switch v.kind {
	case KindUnsigned:
		encodeHead(buf, mtUnsigned, v.uint)
	case KindNegative:
		// Negative -n encodes as major type 1, value (n-1)
		encodeHead(buf, mtNegative, uint64(-v.neg-1))
	case KindByteString:
		encodeHead(buf, mtByteStr, uint64(len(v.bytes)))
		buf.Write(v.bytes)
	case KindTextString:
		encodeHead(buf, mtTextStr, uint64(len(v.str)))
		buf.WriteString(v.str)
	case KindArray:
		encodeHead(buf, mtArray, uint64(len(v.arr)))
		for i := range v.arr {
			if err := encodeValue(buf, &v.arr[i]); err != nil {
				return err
			}
		}
	case KindIntMap:
		// Sort keys: length-first canonical ordering
		entries := make([]IntMapEntry, len(v.intMap))
		copy(entries, v.intMap)
		sortIntMapEntries(entries)
		encodeHead(buf, mtMap, uint64(len(entries)))
		for i := range entries {
			kv := NInt(entries[i].Key)
			if err := encodeValue(buf, &kv); err != nil {
				return err
			}
			if err := encodeValue(buf, &entries[i].Value); err != nil {
				return err
			}
		}
	case KindStrMap:
		// Sort keys: length-first canonical ordering of UTF-8 bytes
		entries := make([]StrMapEntry, len(v.strMap))
		copy(entries, v.strMap)
		sortStrMapEntries(entries)
		encodeHead(buf, mtMap, uint64(len(entries)))
		for i := range entries {
			kv := TStr(entries[i].Key)
			if err := encodeValue(buf, &kv); err != nil {
				return err
			}
			if err := encodeValue(buf, &entries[i].Value); err != nil {
				return err
			}
		}
	case KindBool:
		if v.bool {
			buf.WriteByte(mtSimple | simpleTrue)
		} else {
			buf.WriteByte(mtSimple | simpleFalse)
		}
	case KindNull:
		buf.WriteByte(mtSimple | simpleNull)
	default:
		return errors.New("cbor: cannot encode unknown kind")
	}
	return nil
}

func encodeHead(buf *bytes.Buffer, mt byte, val uint64) {
	if val < 24 {
		buf.WriteByte(mt | byte(val))
	} else if val <= 0xFF {
		buf.WriteByte(mt | aiOneByte)
		buf.WriteByte(byte(val))
	} else if val <= 0xFFFF {
		buf.WriteByte(mt | aiTwoBytes)
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, uint16(val))
		buf.Write(b)
	} else if val <= 0xFFFFFFFF {
		buf.WriteByte(mt | aiFourBytes)
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(val))
		buf.Write(b)
	} else {
		buf.WriteByte(mt | aiEightBytes)
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, val)
		buf.Write(b)
	}
}

// sortIntMapEntries sorts by length-first canonical byte ordering.
// For integer keys: shorter CBOR encoding first, then bytewise.
func sortIntMapEntries(entries []IntMapEntry) {
	sort.SliceStable(entries, func(i, j int) bool {
		return compareIntKeys(entries[i].Key, entries[j].Key) < 0
	})
}

// compareIntKeys compares two integer keys by their canonical CBOR encoding.
// Returns negative if a < b, 0 if equal, positive if a > b.
func compareIntKeys(a, b int64) int {
	ab := encodeIntKey(a)
	bb := encodeIntKey(b)
	return bytes.Compare(ab, bb)
}

func encodeIntKey(n int64) []byte {
	v := NInt(n)
	b, _ := Encode(&v)
	return b
}

// sortStrMapEntries sorts by length-first canonical byte ordering of UTF-8.
func sortStrMapEntries(entries []StrMapEntry) {
	sort.SliceStable(entries, func(i, j int) bool {
		ai, bi := entries[i].Key, entries[j].Key
		if len(ai) != len(bi) {
			return len(ai) < len(bi)
		}
		return ai < bi
	})
}

// Decode decodes CBOR bytes into a Value.
// Returns the decoded value and the number of bytes consumed.
func Decode(data []byte) (*Value, int, error) {
	pos := 0
	v, err := decodeValue(data, &pos)
	if err != nil {
		return nil, 0, err
	}
	return v, pos, nil
}

func decodeValue(data []byte, pos *int) (*Value, error) {
	if *pos >= len(data) {
		return nil, errors.New("cbor: unexpected EOF")
	}
	ib := data[*pos]
	*pos++
	mt := ib & 0xe0
	ai := ib & 0x1f

	arg, err := readArg(data, pos, ai)
	if err != nil {
		return nil, err
	}

	switch mt {
	case mtUnsigned:
		v := UUint(arg)
		return &v, nil
	case mtNegative:
		if arg > uint64(1<<63-1) {
			return nil, fmt.Errorf("cbor: negative integer overflow at offset %d", *pos)
		}
		v := NInt(-int64(arg) - 1)
		return &v, nil
	case mtByteStr:
		end, err := checkedAdd(*pos, int(arg))
		if err != nil {
			return nil, err
		}
		if end > len(data) {
			return nil, errors.New("cbor: byte string truncated")
		}
		b := make([]byte, arg)
		copy(b, data[*pos:end])
		*pos = end
		v := BStr(b)
		return &v, nil
	case mtTextStr:
		end, err := checkedAdd(*pos, int(arg))
		if err != nil {
			return nil, err
		}
		if end > len(data) {
			return nil, errors.New("cbor: text string truncated")
		}
		s := string(data[*pos:end])
		*pos = end
		v := TStr(s)
		return &v, nil
	case mtArray:
		if int(arg) > len(data)-*pos {
			return nil, errors.New("cbor: array length exceeds available data")
		}
		arr := make([]Value, 0, arg)
		for i := uint64(0); i < arg; i++ {
			v, err := decodeValue(data, pos)
			if err != nil {
				return nil, err
			}
			arr = append(arr, *v)
		}
		v := Arr(arr)
		return &v, nil
	case mtMap:
		if int(arg) > len(data)-*pos {
			return nil, errors.New("cbor: map length exceeds available data")
		}
		// Determine if all keys are integers or all strings
		type kv struct{ k, v *Value }
		pairs := make([]kv, 0, arg)
		allInt, allStr := true, true
		for i := uint64(0); i < arg; i++ {
			k, err := decodeValue(data, pos)
			if err != nil {
				return nil, err
			}
			v, err := decodeValue(data, pos)
			if err != nil {
				return nil, err
			}
			if k.kind != KindUnsigned && k.kind != KindNegative {
				allInt = false
			}
			if k.kind != KindTextString {
				allStr = false
			}
			pairs = append(pairs, kv{k, v})
		}
		if allInt {
			entries := make([]IntMapEntry, len(pairs))
			for i, p := range pairs {
				entries[i] = IntMapEntry{Key: p.k.Int(), Value: *p.v}
			}
			v := IMap(entries)
			return &v, nil
		}
		if allStr {
			entries := make([]StrMapEntry, len(pairs))
			for i, p := range pairs {
				entries[i] = StrMapEntry{Key: p.k.Str(), Value: *p.v}
			}
			v := SMap(entries)
			return &v, nil
		}
		return nil, errors.New("cbor: mixed key types in map not supported")
	case mtSimple:
		switch ai {
		case simpleFalse:
			v := Bool(false)
			return &v, nil
		case simpleTrue:
			v := Bool(true)
			return &v, nil
		case simpleNull, simpleUndef:
			v := Null()
			return &v, nil
		default:
			return nil, fmt.Errorf("cbor: unsupported simple value %d", ai)
		}
	default:
		return nil, fmt.Errorf("cbor: unsupported major type %d at offset %d", mt>>5, *pos)
	}
}

func readArg(data []byte, pos *int, ai byte) (uint64, error) {
	switch ai {
	case 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23:
		return uint64(ai), nil
	case aiOneByte:
		if *pos+1 > len(data) {
			return 0, errors.New("cbor: truncated 1-byte argument")
		}
		v := uint64(data[*pos])
		*pos++
		return v, nil
	case aiTwoBytes:
		if *pos+2 > len(data) {
			return 0, errors.New("cbor: truncated 2-byte argument")
		}
		v := uint64(binary.BigEndian.Uint16(data[*pos:]))
		*pos += 2
		return v, nil
	case aiFourBytes:
		if *pos+4 > len(data) {
			return 0, errors.New("cbor: truncated 4-byte argument")
		}
		v := uint64(binary.BigEndian.Uint32(data[*pos:]))
		*pos += 4
		return v, nil
	case aiEightBytes:
		if *pos+8 > len(data) {
			return 0, errors.New("cbor: truncated 8-byte argument")
		}
		v := binary.BigEndian.Uint64(data[*pos:])
		*pos += 8
		return v, nil
	case aiBreak:
		return 0, errors.New("cbor: break code not allowed (no indefinite-length)")
	default:
		return 0, fmt.Errorf("cbor: unsupported additional info %d", ai)
	}
}

func checkedAdd(a, b int) (int, error) {
	if b < 0 {
		return 0, errors.New("cbor: negative length")
	}
	if a > int(^uint(0)>>1)-b {
		return 0, errors.New("cbor: length overflow")
	}
	return a + b, nil
}
