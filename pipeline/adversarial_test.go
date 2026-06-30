package pipeline

import (
	"testing"

	"aafp-go/errors"
	"aafp-go/frame"
	"aafp-go/frameext"
)

func encodeMultiExt(exts ...frameext.Extension) []byte {
	buf, err := frameext.Encode(exts)
	if err != nil {
		panic(err)
	}
	return buf
}

// === Truncation attacks ===

func TestAdvTruncatedHeaderNoAllocation(t *testing.T) {
	ctx := DefaultTestingContext()
	p := New(ctx, nil)
	data := []byte{0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, err := p.Process(data)
	if err == nil {
		t.Fatal("should fail for truncated header")
	}
	pe := err.(*PipelineError)
	if pe.Phase != Phase1ValidateHeader {
		t.Errorf("expected Phase1, got %s", pe.Phase)
	}
	if pe.ErrorCode != errors.MalformedFrame {
		t.Errorf("expected MalformedFrame, got %d", pe.ErrorCode)
	}
}

func TestAdvTruncatedExtensionData(t *testing.T) {
	ctx := DefaultTestingContext()
	p := New(ctx, nil)
	// Extension header says 10 bytes, only 4 present
	extBytes := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0xDE, 0xAD, 0xBE, 0xEF}
	data := makeDataFrame([]byte{0x01}, extBytes)
	_, err := p.Process(data)
	if err == nil {
		t.Fatal("should fail for truncated extension")
	}
	pe := err.(*PipelineError)
	if pe.Phase != Phase15DecodeExtensions {
		t.Errorf("expected Phase15, got %s", pe.Phase)
	}
	if pe.ErrorCode != errors.MalformedFrame {
		t.Errorf("expected MalformedFrame, got %d", pe.ErrorCode)
	}
}

func TestAdvTruncatedExtensionHeader(t *testing.T) {
	ctx := DefaultTestingContext()
	p := New(ctx, nil)
	// Only 3 bytes, less than 8-byte header
	extBytes := []byte{0x00, 0x01, 0x00}
	data := makeDataFrame([]byte{0x01}, extBytes)
	_, err := p.Process(data)
	if err == nil {
		t.Fatal("should fail for truncated extension header")
	}
	pe := err.(*PipelineError)
	if pe.Phase != Phase15DecodeExtensions {
		t.Errorf("expected Phase15, got %s", pe.Phase)
	}
}

// === Extension injection attacks ===

func TestAdvCriticalExtensionInjectionAfterAuthBypass(t *testing.T) {
	ctx := DefaultTestingContext()
	ctx.SigVerified = false // Auth will fail
	p := New(ctx, nil)
	extBytes := encodeExt(0xBEEF, true, []byte{0x01, 0x02})
	data := makeDataFrame([]byte{0x01}, extBytes)
	_, err := p.Process(data)
	if err == nil {
		t.Fatal("should fail")
	}
	pe := err.(*PipelineError)
	// Should fail at Phase 10 (signature), not Phase 16
	if pe.Phase != Phase10VerifySignatures {
		t.Errorf("expected Phase10, got %s", pe.Phase)
	}
}

func TestAdvExtensionInjectionInHandshakeFrame(t *testing.T) {
	ctx := DefaultTestingContext()
	p := New(ctx, nil)
	extBytes := encodeExt(0x0001, false, []byte{0x01})
	data := makeHandshakeFrame([]byte{0xA0}, extBytes)
	_, err := p.Process(data)
	if err == nil {
		t.Fatal("should fail")
	}
	pe := err.(*PipelineError)
	if pe.Phase != Phase15DecodeExtensions {
		t.Errorf("expected Phase15, got %s", pe.Phase)
	}
	if pe.ErrorCode != errors.ProtocolViolation {
		t.Errorf("expected ProtocolViolation, got %d", pe.ErrorCode)
	}
}

func TestAdvNonNegotiatedExtensionInjection(t *testing.T) {
	ctx := DefaultTestingContext()
	ctx.KnownTypes[0x0001] = true
	// 0x0001 not negotiated
	p := New(ctx, nil)
	extBytes := encodeExt(0x0001, false, []byte{0x01})
	data := makeDataFrame([]byte{0x01}, extBytes)
	_, err := p.Process(data)
	if err == nil {
		t.Fatal("should fail")
	}
	pe := err.(*PipelineError)
	if pe.Phase != Phase17CheckNonNegotiated {
		t.Errorf("expected Phase17, got %s", pe.Phase)
	}
	if pe.ErrorCode != errors.InvalidFlags {
		t.Errorf("expected InvalidFlags, got %d", pe.ErrorCode)
	}
}

// === Duplicate extension attacks ===

func TestAdvDuplicateExtensionTypesBothProcessed(t *testing.T) {
	ctx := DefaultTestingContext()
	ctx.KnownTypes[0x0001] = true
	ctx.NegotiatedTypes[0x0001] = true
	p := New(ctx, []ExtensionCallback{testCallback1{}})
	extBytes := encodeMultiExt(
		frameext.Extension{ExtType: 0x0001, Critical: false, Data: []byte{0x01}},
		frameext.Extension{ExtType: 0x0001, Critical: false, Data: []byte{0x02}},
	)
	data := makeDataFrame([]byte{0x01}, extBytes)
	result, err := p.Process(data)
	if err != nil {
		t.Fatalf("should succeed: %v", err)
	}
	if result.ExtensionCallbackCount != 2 {
		t.Errorf("expected 2 callbacks, got %d", result.ExtensionCallbackCount)
	}
}

func TestAdvDuplicateCriticalExtensionTypesRejected(t *testing.T) {
	ctx := DefaultTestingContext()
	p := New(ctx, nil)
	extBytes := encodeMultiExt(
		frameext.Extension{ExtType: 0xBEEF, Critical: true, Data: []byte{0x01}},
		frameext.Extension{ExtType: 0xBEEF, Critical: true, Data: []byte{0x02}},
	)
	data := makeDataFrame([]byte{0x01}, extBytes)
	_, err := p.Process(data)
	if err == nil {
		t.Fatal("should fail")
	}
	pe := err.(*PipelineError)
	if pe.Phase != Phase16CheckUnknownCritical {
		t.Errorf("expected Phase16, got %s", pe.Phase)
	}
}

// === Oversized frame injection ===

func TestAdvOversizedPayloadNoAllocation(t *testing.T) {
	ctx := DefaultTestingContext()
	p := New(ctx, nil)
	data := make([]byte, frame.HeaderSize+4)
	data[0] = frame.Version
	data[1] = frame.TypeData
	data[2] = 0
	data[3] = 0
	data[11] = 4 // stream_id
	// payload_len = 2MB
	data[12] = 0
	data[13] = 0
	data[14] = 0
	data[15] = 0
	data[16] = 0
	data[17] = 0x20
	data[18] = 0x00
	data[19] = 0x00
	// ext_len = 0
	_, err := p.Process(data)
	if err == nil {
		t.Fatal("should fail")
	}
	pe := err.(*PipelineError)
	if pe.Phase != Phase2ValidateLengths {
		t.Errorf("expected Phase2, got %s", pe.Phase)
	}
	if pe.ErrorCode != errors.FrameTooLarge {
		t.Errorf("expected FrameTooLarge, got %d", pe.ErrorCode)
	}
	if pe.Fatal {
		t.Error("should be non-fatal")
	}
}

// === CBOR injection attacks ===

func TestAdvNonCanonicalCborInjection(t *testing.T) {
	ctx := DefaultTestingContext()
	p := New(ctx, nil)
	// Non-canonical CBOR: value 5 as 0x18 0x05 instead of 0x05
	data := makeHandshakeFrame([]byte{0x18, 0x05}, nil)
	_, err := p.Process(data)
	if err == nil {
		t.Fatal("should fail")
	}
	pe := err.(*PipelineError)
	if pe.Phase != Phase6DecodeCbor {
		t.Errorf("expected Phase6, got %s", pe.Phase)
	}
	if pe.ErrorCode != errors.SerializationError {
		t.Errorf("expected SerializationError, got %d", pe.ErrorCode)
	}
}

func TestAdvDuplicateCborKeysInjection(t *testing.T) {
	ctx := DefaultTestingContext()
	p := New(ctx, nil)
	// CBOR map with duplicate keys: {1: "a", 1: "b"}
	payload := []byte{0xA2, 0x01, 0x61, 0x61, 0x01, 0x61, 0x62}
	data := makeHandshakeFrame(payload, nil)
	_, err := p.Process(data)
	if err == nil {
		t.Fatal("should fail")
	}
	pe := err.(*PipelineError)
	if pe.Phase != Phase6DecodeCbor {
		t.Errorf("expected Phase6, got %s", pe.Phase)
	}
	if pe.ErrorCode != errors.SerializationError {
		t.Errorf("expected SerializationError, got %d", pe.ErrorCode)
	}
}

// === Reserved field manipulation ===

func TestAdvReservedFieldNonzeroRejected(t *testing.T) {
	ctx := DefaultTestingContext()
	p := New(ctx, nil)
	data := makeDataFrame([]byte{0x01}, nil)
	data[3] = 0x42
	_, err := p.Process(data)
	if err == nil {
		t.Fatal("should fail")
	}
	pe := err.(*PipelineError)
	if pe.Phase != Phase1ValidateHeader {
		t.Errorf("expected Phase1, got %s", pe.Phase)
	}
	if pe.ErrorCode != errors.ReservedFieldNonzero {
		t.Errorf("expected ReservedFieldNonzero, got %d", pe.ErrorCode)
	}
}

// === Version field manipulation ===

func TestAdvVersionZeroRejected(t *testing.T) {
	ctx := DefaultTestingContext()
	p := New(ctx, nil)
	data := makeDataFrame([]byte{0x01}, nil)
	data[0] = 0
	_, err := p.Process(data)
	if err == nil {
		t.Fatal("should fail")
	}
	pe := err.(*PipelineError)
	if pe.Phase != Phase1ValidateHeader {
		t.Errorf("expected Phase1, got %s", pe.Phase)
	}
	if pe.ErrorCode != errors.InvalidVersion {
		t.Errorf("expected InvalidVersion, got %d", pe.ErrorCode)
	}
}

func TestAdvVersion255Rejected(t *testing.T) {
	ctx := DefaultTestingContext()
	p := New(ctx, nil)
	data := makeDataFrame([]byte{0x01}, nil)
	data[0] = 255
	_, err := p.Process(data)
	if err == nil {
		t.Fatal("should fail")
	}
	pe := err.(*PipelineError)
	if pe.Phase != Phase1ValidateHeader {
		t.Errorf("expected Phase1, got %s", pe.Phase)
	}
	if pe.ErrorCode != errors.InvalidVersion {
		t.Errorf("expected InvalidVersion, got %d", pe.ErrorCode)
	}
}

// === Mixed attacks ===

func TestAdvMixedAttackOversizedAndInvalidVersion(t *testing.T) {
	ctx := DefaultTestingContext()
	p := New(ctx, nil)
	data := make([]byte, frame.HeaderSize+4)
	data[0] = 99 // Invalid version
	data[1] = frame.TypeData
	data[11] = 4
	data[17] = 0x20 // 2MB payload
	_, err := p.Process(data)
	if err == nil {
		t.Fatal("should fail")
	}
	pe := err.(*PipelineError)
	if pe.Phase != Phase1ValidateHeader {
		t.Errorf("expected Phase1 (version before size), got %s", pe.Phase)
	}
}

func TestAdvMixedAttackInvalidSignatureAndCriticalExtension(t *testing.T) {
	ctx := DefaultTestingContext()
	ctx.SigVerified = false
	p := New(ctx, nil)
	extBytes := encodeExt(0xBEEF, true, []byte{0x01})
	data := makeDataFrame([]byte{0x01}, extBytes)
	_, err := p.Process(data)
	if err == nil {
		t.Fatal("should fail")
	}
	pe := err.(*PipelineError)
	if pe.Phase != Phase10VerifySignatures {
		t.Errorf("expected Phase10 (signature before extension), got %s", pe.Phase)
	}
}

// === Phase bypass attempts ===

func TestAdvCannotBypassAuthWithKnownExtension(t *testing.T) {
	ctx := DefaultTestingContext()
	ctx.SigVerified = false
	ctx.KnownTypes[0x0001] = true
	ctx.NegotiatedTypes[0x0001] = true
	p := New(ctx, []ExtensionCallback{testCallback1{}})
	extBytes := encodeExt(0x0001, false, []byte{0x01})
	data := makeDataFrame([]byte{0x01}, extBytes)
	_, err := p.Process(data)
	if err == nil {
		t.Fatal("should fail")
	}
	pe := err.(*PipelineError)
	if pe.Phase != Phase10VerifySignatures {
		t.Errorf("expected Phase10, got %s", pe.Phase)
	}
	if pe.ExtensionCallbacksInvoked() {
		t.Error("callbacks should not be invoked")
	}
}

func TestAdvCannotBypassAuthWithCriticalKnownExtension(t *testing.T) {
	ctx := DefaultTestingContext()
	ctx.SigVerified = false
	ctx.KnownTypes[0x0001] = true
	ctx.NegotiatedTypes[0x0001] = true
	p := New(ctx, []ExtensionCallback{testCallback1{}})
	extBytes := encodeExt(0x0001, true, []byte{0x01}) // Critical
	data := makeDataFrame([]byte{0x01}, extBytes)
	_, err := p.Process(data)
	if err == nil {
		t.Fatal("should fail")
	}
	pe := err.(*PipelineError)
	if pe.Phase != Phase10VerifySignatures {
		t.Errorf("expected Phase10, got %s", pe.Phase)
	}
}
