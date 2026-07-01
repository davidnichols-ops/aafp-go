// Package frame implements the AAFP v1 frame format per RFC-0002 Section 3.
//
// Frame header layout (28 bytes, all big-endian):
//
//	[0]     Version (8 bits) — MUST be 1
//	[1]     FrameType (8 bits)
//	[2]     Flags (8 bits)
//	[3]     Reserved (8 bits) — MUST be 0 on send, ignored on receive
//	[4..12] Stream ID (64 bits)
//	[12..20] Payload Length (64 bits)
//	[20..28] Extension Length (64 bits)
//
// Frame body (after header):
//
//	Extensions (Extension Length bytes)
//	Payload (Payload Length bytes)
package frame

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	Version          = 1
	HeaderSize       = 28
	MaxPayloadSize   = 1 << 20   // 1 MiB
	MaxExtensionSize = 64 * 1024 // 64 KiB (RFC-0002 §6.1, A-5)
)

// Frame types (RFC-0002 §4)
const (
	TypeData        = 0x01
	TypeHandshake   = 0x02
	TypeRPCRequest  = 0x03
	TypeRPCResponse = 0x04
	TypeClose       = 0x05
	TypeError_      = 0x06
	TypePing        = 0x07
	TypePong        = 0x08
)

// Flags
const (
	FlagMore       = 0x01
	FlagCompressed = 0x02
	FlagCritical   = 0x80
)

// Frame represents a decoded AAFP frame.
type Frame struct {
	Version    byte
	FrameType  byte
	Flags      byte
	StreamID   uint64
	Extensions []byte
	Payload    []byte
}

// Encode serializes a Frame to wire bytes.
func Encode(f *Frame) ([]byte, error) {
	if len(f.Payload) > MaxPayloadSize {
		return nil, fmt.Errorf("frame: payload too large (%d > %d)",
			len(f.Payload), MaxPayloadSize)
	}
	if len(f.Extensions) > MaxExtensionSize {
		return nil, fmt.Errorf("frame: extension section too large (%d > %d)",
			len(f.Extensions), MaxExtensionSize)
	}
	totalBody := len(f.Extensions) + len(f.Payload)
	buf := make([]byte, HeaderSize+totalBody)
	buf[0] = f.Version
	buf[1] = f.FrameType
	buf[2] = f.Flags
	buf[3] = 0 // reserved
	binary.BigEndian.PutUint64(buf[4:12], f.StreamID)
	binary.BigEndian.PutUint64(buf[12:20], uint64(len(f.Payload)))
	binary.BigEndian.PutUint64(buf[20:28], uint64(len(f.Extensions)))
	copy(buf[HeaderSize:], f.Extensions)
	copy(buf[HeaderSize+len(f.Extensions):], f.Payload)
	return buf, nil
}

// Decode parses wire bytes into a Frame.
// Returns the frame and the total number of bytes consumed.
func Decode(data []byte) (*Frame, int, error) {
	if len(data) < HeaderSize {
		return nil, 0, fmt.Errorf("frame: need %d bytes, have %d", HeaderSize, len(data))
	}
	version := data[0]
	if version != Version {
		return nil, 0, fmt.Errorf("frame: invalid version %d (expected %d)", version, Version)
	}
	frameType := data[1]
	flags := data[2]
	streamID := binary.BigEndian.Uint64(data[4:12])
	payloadLen := binary.BigEndian.Uint64(data[12:20])
	extLen := binary.BigEndian.Uint64(data[20:28])

	if payloadLen > MaxPayloadSize {
		return nil, 0, fmt.Errorf("frame: payload too large (%d > %d)", payloadLen, MaxPayloadSize)
	}

	// Reject oversized extensions BEFORE any allocation (A-5)
	if extLen > MaxExtensionSize {
		return nil, 0, fmt.Errorf("frame: extension section too large (%d > %d)", extLen, MaxExtensionSize)
	}

	// Checked addition to prevent overflow
	totalBody, err := safeAdd64(extLen, payloadLen)
	if err != nil {
		return nil, 0, err
	}
	totalFrame, err := safeAdd64(uint64(HeaderSize), totalBody)
	if err != nil {
		return nil, 0, err
	}
	if uint64(len(data)) < totalFrame {
		return nil, 0, fmt.Errorf("frame: incomplete (need %d, have %d)", totalFrame, len(data))
	}

	// Validate frame type per RFC-0006 §4.2:
	// - Known types: always valid
	// - Unknown + critical bit: reject (caller sends ERROR 8004)
	// - Unknown + non-critical: decode succeeds, caller MUST skip
	if !isValidFrameType(frameType, flags) {
		if (flags & FlagCritical) != 0 {
			return nil, 0, fmt.Errorf("frame: unknown critical frame type 0x%02x", frameType)
		}
		// Non-critical unknown: decode succeeds, caller should skip
	}

	ext := make([]byte, extLen)
	copy(ext, data[HeaderSize:HeaderSize+int(extLen)])

	payload := make([]byte, payloadLen)
	copy(payload, data[HeaderSize+int(extLen):int(totalFrame)])

	f := &Frame{
		Version:    version,
		FrameType:  frameType,
		Flags:      flags,
		StreamID:   streamID,
		Extensions: ext,
		Payload:    payload,
	}
	return f, int(totalFrame), nil
}

// isValidFrameType checks whether a frame type is known.
// Per RFC-0006 §4.2:
//   - Known frame types (0x01-0x08) are always valid.
//   - Unknown frame types with the critical bit set (0x80) MUST be rejected
//     with error 8004 (UNKNOWN_CRITICAL_FRAME_TYPE).
//   - Unknown frame types without the critical bit MUST be skipped (the
//     receiver continues processing). Decode returns the frame with
//     IsUnknown=true so the caller can skip it.
//
// This function returns true if the frame type is known.
// Callers must separately check the critical bit for unknown types.
func isValidFrameType(ft, flags byte) bool {
	switch ft {
	case TypeData, TypeHandshake, TypeRPCRequest, TypeRPCResponse,
		TypeClose, TypeError_, TypePing, TypePong:
		return true
	}
	return false
}

// IsKnownFrameType returns true if the frame type is in the v1 registry
// (RFC-0006 §4.1).
func IsKnownFrameType(ft byte) bool {
	return isValidFrameType(ft, 0)
}

// IsCriticalUnknownFrameType returns true if the frame type is unknown
// AND the critical bit (0x80) is set in the flags. Per RFC-0006 §4.2,
// such frames MUST be rejected with error 8004.
func IsCriticalUnknownFrameType(ft, flags byte) bool {
	return !isValidFrameType(ft, flags) && (flags&FlagCritical) != 0
}

// IsSkippableUnknownFrameType returns true if the frame type is unknown
// AND the critical bit is NOT set. Per RFC-0006 §4.2, such frames MUST
// be skipped by the receiver (the connection continues).
func IsSkippableUnknownFrameType(ft, flags byte) bool {
	return !isValidFrameType(ft, flags) && (flags&FlagCritical) == 0
}

func safeAdd64(a, b uint64) (uint64, error) {
	if a > ^uint64(0)-b {
		return 0, errors.New("frame: length overflow")
	}
	return a + b, nil
}
