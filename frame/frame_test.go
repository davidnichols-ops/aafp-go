package frame

import (
	"encoding/binary"
	"testing"
)

func TestEncodeDecodeDataFrame(t *testing.T) {
	f := &Frame{
		Version:    Version,
		FrameType:  TypeData,
		Flags:      0,
		StreamID:   4,
		Extensions: nil,
		Payload:    []byte("hello world"),
	}
	encoded, err := Encode(f)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	if len(encoded) != HeaderSize+11 {
		t.Fatalf("expected %d bytes, got %d", HeaderSize+11, len(encoded))
	}

	decoded, consumed, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}
	if consumed != len(encoded) {
		t.Fatalf("expected consumed %d, got %d", len(encoded), consumed)
	}
	if decoded.FrameType != TypeData {
		t.Fatalf("expected frame type %d, got %d", TypeData, decoded.FrameType)
	}
	if decoded.StreamID != 4 {
		t.Fatalf("expected stream ID 4, got %d", decoded.StreamID)
	}
	if string(decoded.Payload) != "hello world" {
		t.Fatalf("expected payload 'hello world', got %q", decoded.Payload)
	}
}

func TestEncodeDecodeWithExtensions(t *testing.T) {
	f := &Frame{
		Version:    Version,
		FrameType:  TypeData,
		StreamID:   1,
		Extensions: []byte{0x00, 0x01, 0x02, 0x03},
		Payload:    []byte("payload"),
	}
	encoded, err := Encode(f)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, _, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}
	if len(decoded.Extensions) != 4 {
		t.Fatalf("expected 4 extension bytes, got %d", len(decoded.Extensions))
	}
	if decoded.Extensions[0] != 0x00 || decoded.Extensions[3] != 0x03 {
		t.Fatalf("extension bytes mismatch: %v", decoded.Extensions)
	}
}

func TestPayloadTooLargeEncode(t *testing.T) {
	f := &Frame{
		Version:    Version,
		FrameType:  TypeData,
		StreamID:   1,
		Payload:    make([]byte, MaxPayloadSize+1),
	}
	_, err := Encode(f)
	if err == nil {
		t.Fatal("expected error for oversized payload, got nil")
	}
}

func TestPayloadTooLargeDecode(t *testing.T) {
	header := make([]byte, HeaderSize)
	header[0] = Version
	header[1] = TypeData
	binary.BigEndian.PutUint64(header[12:20], uint64(MaxPayloadSize+1))
	binary.BigEndian.PutUint64(header[20:28], 0)
	_, _, err := Decode(header)
	if err == nil {
		t.Fatal("expected error for oversized payload in decode, got nil")
	}
}

// A-5: Extension size limit tests

func TestExtensionTooLargeEncode(t *testing.T) {
	f := &Frame{
		Version:    Version,
		FrameType:  TypeData,
		StreamID:   1,
		Extensions: make([]byte, MaxExtensionSize+1),
		Payload:    []byte("test"),
	}
	_, err := Encode(f)
	if err == nil {
		t.Fatal("expected error for oversized extension, got nil")
	}
}

func TestExtensionTooLargeDecode(t *testing.T) {
	// Craft a header with extLen > MaxExtensionSize but payloadLen = 0
	// so we don't need to allocate the actual extension bytes.
	header := make([]byte, HeaderSize)
	header[0] = Version
	header[1] = TypeData
	binary.BigEndian.PutUint64(header[12:20], 0) // payload len = 0
	binary.BigEndian.PutUint64(header[20:28], uint64(MaxExtensionSize+1))
	_, _, err := Decode(header)
	if err == nil {
		t.Fatal("expected error for oversized extension in decode, got nil")
	}
}

func TestExtensionAtMaxSize(t *testing.T) {
	// Extension at exactly the limit should succeed
	f := &Frame{
		Version:    Version,
		FrameType:  TypeData,
		StreamID:   1,
		Extensions: make([]byte, MaxExtensionSize),
		Payload:    []byte("ok"),
	}
	encoded, err := Encode(f)
	if err != nil {
		t.Fatalf("Encode at max extension size failed: %v", err)
	}

	decoded, _, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode at max extension size failed: %v", err)
	}
	if len(decoded.Extensions) != MaxExtensionSize {
		t.Fatalf("expected %d extension bytes, got %d", MaxExtensionSize, len(decoded.Extensions))
	}
}

func TestExtensionZeroSize(t *testing.T) {
	f := &Frame{
		Version:    Version,
		FrameType:  TypeData,
		StreamID:   1,
		Extensions: nil,
		Payload:    []byte("test"),
	}
	encoded, err := Encode(f)
	if err != nil {
		t.Fatalf("Encode with nil extensions failed: %v", err)
	}

	decoded, _, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode with zero extensions failed: %v", err)
	}
	if len(decoded.Extensions) != 0 {
		t.Fatalf("expected 0 extension bytes, got %d", len(decoded.Extensions))
	}
}

func TestInvalidVersion(t *testing.T) {
	header := make([]byte, HeaderSize)
	header[0] = 99 // wrong version
	header[1] = TypeData
	_, _, err := Decode(header)
	if err == nil {
		t.Fatal("expected error for invalid version, got nil")
	}
}

func TestUnknownCriticalFrameType(t *testing.T) {
	f := &Frame{
		Version:    Version,
		FrameType:  0xFF, // unknown
		Flags:      FlagCritical,
		StreamID:   1,
		Payload:    []byte("test"),
	}
	encoded, err := Encode(f)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	_, _, err = Decode(encoded)
	if err == nil {
		t.Fatal("expected error for unknown critical frame type, got nil")
	}
}

func TestUnknownNonCriticalFrameType(t *testing.T) {
	f := &Frame{
		Version:    Version,
		FrameType:  0xFF, // unknown
		Flags:      0,    // no critical bit
		StreamID:   1,
		Payload:    []byte("test"),
	}
	encoded, err := Encode(f)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	decoded, _, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode of non-critical unknown type failed: %v", err)
	}
	if decoded.FrameType != 0xFF {
		t.Fatalf("expected frame type 0xFF, got 0x%02x", decoded.FrameType)
	}
}

func TestMultipleFrames(t *testing.T) {
	f1 := &Frame{
		Version:   Version,
		FrameType: TypeData,
		StreamID:  1,
		Payload:   []byte("first"),
	}
	f2 := &Frame{
		Version:   Version,
		FrameType: TypeData,
		StreamID:  2,
		Payload:   []byte("second"),
	}
	e1, err := Encode(f1)
	if err != nil {
		t.Fatalf("Encode f1 failed: %v", err)
	}
	e2, err := Encode(f2)
	if err != nil {
		t.Fatalf("Encode f2 failed: %v", err)
	}
	buf := append(e1, e2...)

	decoded1, consumed1, err := Decode(buf)
	if err != nil {
		t.Fatalf("Decode first frame failed: %v", err)
	}
	if string(decoded1.Payload) != "first" {
		t.Fatalf("expected 'first', got %q", decoded1.Payload)
	}

	decoded2, _, err := Decode(buf[consumed1:])
	if err != nil {
		t.Fatalf("Decode second frame failed: %v", err)
	}
	if string(decoded2.Payload) != "second" {
		t.Fatalf("expected 'second', got %q", decoded2.Payload)
	}
}

func TestIncompleteFrame(t *testing.T) {
	data := make([]byte, 10) // less than HeaderSize
	_, _, err := Decode(data)
	if err == nil {
		t.Fatal("expected error for incomplete frame, got nil")
	}
}
