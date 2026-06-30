package pipeline

import (
	"testing"

	"aafp-go/errors"
	"aafp-go/frame"
	"aafp-go/frameext"
)

func makeDataFrame(payload, extensions []byte) []byte {
	f := &frame.Frame{
		Version:    frame.Version,
		FrameType:  frame.TypeData,
		Flags:      0,
		StreamID:   4,
		Extensions: extensions,
		Payload:    payload,
	}
	buf, err := frame.Encode(f)
	if err != nil {
		panic(err)
	}
	return buf
}

func makeHandshakeFrame(payload, extensions []byte) []byte {
	f := &frame.Frame{
		Version:    frame.Version,
		FrameType:  frame.TypeHandshake,
		Flags:      0,
		StreamID:   0,
		Extensions: extensions,
		Payload:    payload,
	}
	buf, err := frame.Encode(f)
	if err != nil {
		panic(err)
	}
	return buf
}

func encodeExt(extType uint16, critical bool, data []byte) []byte {
	exts := []frameext.Extension{
		{ExtType: extType, Critical: critical, Data: data},
	}
	buf, err := frameext.Encode(exts)
	if err != nil {
		panic(err)
	}
	return buf
}

// === Phase 1 tests ===

func TestPhase1ValidHeader(t *testing.T) {
	ctx := DefaultTestingContext()
	p := New(ctx, nil)
	data := makeDataFrame([]byte{0x01, 0x02}, nil)
	result, err := p.Process(data)
	if err != nil {
		t.Fatalf("valid frame should pass: %v", err)
	}
	_ = result
}

func TestPhase1InvalidVersion(t *testing.T) {
	ctx := DefaultTestingContext()
	p := New(ctx, nil)
	data := makeDataFrame([]byte{0x01}, nil)
	data[0] = 99 // Invalid version
	_, err := p.Process(data)
	if err == nil {
		t.Fatal("should fail for invalid version")
	}
	pe, ok := err.(*PipelineError)
	if !ok {
		t.Fatalf("expected *PipelineError, got %T", err)
	}
	if pe.Phase != Phase1ValidateHeader {
		t.Errorf("expected Phase1, got %s", pe.Phase)
	}
	if pe.ErrorCode != errors.InvalidVersion {
		t.Errorf("expected InvalidVersion, got %d", pe.ErrorCode)
	}
	if !pe.Fatal {
		t.Error("should be fatal")
	}
	if pe.ExtensionCallbacksInvoked() {
		t.Error("callbacks should not be invoked")
	}
}

func TestPhase1ReservedNonzero(t *testing.T) {
	ctx := DefaultTestingContext()
	p := New(ctx, nil)
	data := makeDataFrame([]byte{0x01}, nil)
	data[3] = 0xFF // Reserved field non-zero
	_, err := p.Process(data)
	if err == nil {
		t.Fatal("should fail for reserved nonzero")
	}
	pe := err.(*PipelineError)
	if pe.Phase != Phase1ValidateHeader {
		t.Errorf("expected Phase1, got %s", pe.Phase)
	}
	if pe.ErrorCode != errors.ReservedFieldNonzero {
		t.Errorf("expected ReservedFieldNonzero, got %d", pe.ErrorCode)
	}
}

// === Phase 2-3 tests ===

func TestPhase2OversizedExtension(t *testing.T) {
	ctx := DefaultTestingContext()
	p := New(ctx, nil)
	// Create a frame header with ext_len = 70000 (exceeds 64 KiB)
	data := make([]byte, frame.HeaderSize+100)
	data[0] = frame.Version
	data[1] = frame.TypeData
	data[2] = 0
	data[3] = 0
	// stream_id = 4
	for i := 4; i < 12; i++ {
		data[i] = 0
	}
	data[11] = 4
	// payload_len = 100
	for i := 12; i < 20; i++ {
		data[i] = 0
	}
	data[19] = 100
	// ext_len = 70000 (0x11170)
	data[20] = 0
	data[21] = 0
	data[22] = 0
	data[23] = 0
	data[24] = 0
	data[25] = 0x01
	data[26] = 0x11
	data[27] = 0x70

	_, err := p.Process(data)
	if err == nil {
		t.Fatal("should fail for oversized extension")
	}
	pe := err.(*PipelineError)
	if pe.Phase != Phase2ValidateLengths {
		t.Errorf("expected Phase2, got %s", pe.Phase)
	}
	if pe.ErrorCode != errors.FrameTooLarge {
		t.Errorf("expected FrameTooLarge, got %d", pe.ErrorCode)
	}
	if pe.Fatal {
		t.Error("should be non-fatal (stream-level)")
	}
}

// === Phase 10 tests ===

func TestPhase10InvalidSignature(t *testing.T) {
	ctx := DefaultTestingContext()
	ctx.SigVerified = false
	p := New(ctx, nil)
	data := makeDataFrame([]byte{0x01}, nil)
	_, err := p.Process(data)
	pe := err.(*PipelineError)
	if pe.Phase != Phase10VerifySignatures {
		t.Errorf("expected Phase10, got %s", pe.Phase)
	}
	if pe.ErrorCode != errors.InvalidSignature {
		t.Errorf("expected InvalidSignature, got %d", pe.ErrorCode)
	}
	if pe.ExtensionCallbacksInvoked() {
		t.Error("callbacks should not be invoked")
	}
}

// === Phase 11 tests ===

func TestPhase11InvalidAgentId(t *testing.T) {
	ctx := DefaultTestingContext()
	ctx.AgentIDOk = false
	p := New(ctx, nil)
	data := makeDataFrame([]byte{0x01}, nil)
	_, err := p.Process(data)
	pe := err.(*PipelineError)
	if pe.Phase != Phase11VerifyAgentId {
		t.Errorf("expected Phase11, got %s", pe.Phase)
	}
	if pe.ErrorCode != errors.InvalidAgentId {
		t.Errorf("expected InvalidAgentId, got %d", pe.ErrorCode)
	}
}

// === Phase 12 tests ===

func TestPhase12InvalidSessionState(t *testing.T) {
	ctx := DefaultTestingContext()
	ctx.SessionValid = false
	p := New(ctx, nil)
	data := makeDataFrame([]byte{0x01}, nil)
	_, err := p.Process(data)
	pe := err.(*PipelineError)
	if pe.Phase != Phase12VerifySessionState {
		t.Errorf("expected Phase12, got %s", pe.Phase)
	}
	if pe.ErrorCode != errors.ProtocolViolation {
		t.Errorf("expected ProtocolViolation, got %d", pe.ErrorCode)
	}
}

// === Phase 13 tests ===

func TestPhase13Unauthorized(t *testing.T) {
	ctx := DefaultTestingContext()
	ctx.AuthorizedOk = false
	p := New(ctx, nil)
	data := makeDataFrame([]byte{0x01}, nil)
	_, err := p.Process(data)
	pe := err.(*PipelineError)
	if pe.Phase != Phase13VerifyAuthorization {
		t.Errorf("expected Phase13, got %s", pe.Phase)
	}
	if pe.ErrorCode != errors.Unauthorized {
		t.Errorf("expected Unauthorized, got %d", pe.ErrorCode)
	}
}

// === Phase 14 tests ===

func TestPhase14InsufficientCapability(t *testing.T) {
	ctx := DefaultTestingContext()
	ctx.CapabilitiesOk = false
	p := New(ctx, nil)
	data := makeDataFrame([]byte{0x01}, nil)
	_, err := p.Process(data)
	pe := err.(*PipelineError)
	if pe.Phase != Phase14VerifyCapabilities {
		t.Errorf("expected Phase14, got %s", pe.Phase)
	}
	if pe.ErrorCode != errors.InsufficientCapability {
		t.Errorf("expected InsufficientCapability, got %d", pe.ErrorCode)
	}
}

// === Phase 15 tests ===

func TestPhase15HandshakeWithExtensionsRejected(t *testing.T) {
	ctx := DefaultTestingContext()
	p := New(ctx, nil)
	extBytes := encodeExt(0x0001, false, []byte{0x01})
	data := makeHandshakeFrame([]byte{0xA0}, extBytes) // 0xA0 = empty CBOR map
	_, err := p.Process(data)
	pe := err.(*PipelineError)
	if pe.Phase != Phase15DecodeExtensions {
		t.Errorf("expected Phase15, got %s", pe.Phase)
	}
	if pe.ErrorCode != errors.ProtocolViolation {
		t.Errorf("expected ProtocolViolation, got %d", pe.ErrorCode)
	}
}

// === Phase 16 tests ===

func TestPhase16UnknownCriticalExtension(t *testing.T) {
	ctx := DefaultTestingContext()
	p := New(ctx, nil)
	extBytes := encodeExt(0xBEEF, true, []byte{0x01, 0x02})
	data := makeDataFrame([]byte{0x01}, extBytes)
	_, err := p.Process(data)
	pe := err.(*PipelineError)
	if pe.Phase != Phase16CheckUnknownCritical {
		t.Errorf("expected Phase16, got %s", pe.Phase)
	}
	if pe.ErrorCode != errors.UnknownCriticalExtension {
		t.Errorf("expected UnknownCriticalExtension, got %d", pe.ErrorCode)
	}
}

// === Phase 17 tests ===

func TestPhase17NonNegotiatedExtension(t *testing.T) {
	ctx := DefaultTestingContext()
	ctx.KnownTypes[0x0001] = true
	// 0x0001 is known but not negotiated
	p := New(ctx, nil)
	extBytes := encodeExt(0x0001, false, []byte{0x01})
	data := makeDataFrame([]byte{0x01}, extBytes)
	_, err := p.Process(data)
	pe := err.(*PipelineError)
	if pe.Phase != Phase17CheckNonNegotiated {
		t.Errorf("expected Phase17, got %s", pe.Phase)
	}
	if pe.ErrorCode != errors.InvalidFlags {
		t.Errorf("expected InvalidFlags, got %d", pe.ErrorCode)
	}
}

// === Phase 18 tests ===

type testCallback1 struct{}

func (testCallback1) ExtensionType() uint16 { return 0x0001 }
func (testCallback1) Process(_ []byte) error { return nil }

type testCallback2 struct{}

func (testCallback2) ExtensionType() uint16 { return 0x0002 }
func (testCallback2) Process(_ []byte) error { return nil }

func TestPhase18CallbackInvokedForValidExtension(t *testing.T) {
	ctx := DefaultTestingContext()
	ctx.KnownTypes[0x0001] = true
	ctx.NegotiatedTypes[0x0001] = true
	callbacks := []ExtensionCallback{testCallback1{}}
	p := New(ctx, callbacks)
	extBytes := encodeExt(0x0001, false, []byte{0xDE, 0xAD})
	data := makeDataFrame([]byte{0x01}, extBytes)
	result, err := p.Process(data)
	if err != nil {
		t.Fatalf("should succeed: %v", err)
	}
	if result.ExtensionCallbackCount != 1 {
		t.Errorf("expected 1 callback, got %d", result.ExtensionCallbackCount)
	}
	if result.ExtensionsIgnored != 0 {
		t.Errorf("expected 0 ignored, got %d", result.ExtensionsIgnored)
	}
}

func TestPhase18UnknownNonCriticalIgnored(t *testing.T) {
	ctx := DefaultTestingContext()
	p := New(ctx, nil)
	extBytes := encodeExt(0xBEEF, false, []byte{0x01})
	data := makeDataFrame([]byte{0x01}, extBytes)
	result, err := p.Process(data)
	if err != nil {
		t.Fatalf("should succeed: %v", err)
	}
	if result.ExtensionCallbackCount != 0 {
		t.Errorf("expected 0 callbacks, got %d", result.ExtensionCallbackCount)
	}
	if result.ExtensionsIgnored != 1 {
		t.Errorf("expected 1 ignored, got %d", result.ExtensionsIgnored)
	}
}

func TestPhase18MultipleExtensions(t *testing.T) {
	ctx := DefaultTestingContext()
	ctx.KnownTypes[0x0001] = true
	ctx.KnownTypes[0x0002] = true
	ctx.NegotiatedTypes[0x0001] = true
	ctx.NegotiatedTypes[0x0002] = true
	callbacks := []ExtensionCallback{testCallback1{}, testCallback2{}}
	p := New(ctx, callbacks)
	exts := []frameext.Extension{
		{ExtType: 0x0001, Critical: false, Data: []byte{0x01}},
		{ExtType: 0x0002, Critical: false, Data: []byte{0x02}},
	}
	extBytes, _ := frameext.Encode(exts)
	data := makeDataFrame([]byte{0x01}, extBytes)
	result, err := p.Process(data)
	if err != nil {
		t.Fatalf("should succeed: %v", err)
	}
	if result.ExtensionCallbackCount != 2 {
		t.Errorf("expected 2 callbacks, got %d", result.ExtensionCallbackCount)
	}
}

// === Full pipeline success test ===

func TestFullPipelineSuccessNoExtensions(t *testing.T) {
	ctx := DefaultTestingContext()
	p := New(ctx, nil)
	data := makeDataFrame([]byte{0x01, 0x02, 0x03}, nil)
	result, err := p.Process(data)
	if err != nil {
		t.Fatalf("should succeed: %v", err)
	}
	if result.ExtensionCallbackCount != 0 {
		t.Errorf("expected 0 callbacks, got %d", result.ExtensionCallbackCount)
	}
	if len(result.Extensions) != 0 {
		t.Errorf("expected 0 extensions, got %d", len(result.Extensions))
	}
}

// === Callback count is zero for all pre-auth failures ===

func TestCallbackCountZeroForAllPreAuthFailures(t *testing.T) {
	tests := []struct {
		name string
		ctx  *TestingContext
	}{
		{"invalid signature", &TestingContext{
			SigVerified: false, AgentIDOk: true, SessionValid: true,
			AuthorizedOk: true, CapabilitiesOk: true, TranscriptValid: true,
			NegotiatedTypes: map[uint16]bool{}, KnownTypes: map[uint16]bool{},
		}},
		{"invalid agent id", &TestingContext{
			SigVerified: true, AgentIDOk: false, SessionValid: true,
			AuthorizedOk: true, CapabilitiesOk: true, TranscriptValid: true,
			NegotiatedTypes: map[uint16]bool{}, KnownTypes: map[uint16]bool{},
		}},
		{"invalid session", &TestingContext{
			SigVerified: true, AgentIDOk: true, SessionValid: false,
			AuthorizedOk: true, CapabilitiesOk: true, TranscriptValid: true,
			NegotiatedTypes: map[uint16]bool{}, KnownTypes: map[uint16]bool{},
		}},
		{"unauthorized", &TestingContext{
			SigVerified: true, AgentIDOk: true, SessionValid: true,
			AuthorizedOk: false, CapabilitiesOk: true, TranscriptValid: true,
			NegotiatedTypes: map[uint16]bool{}, KnownTypes: map[uint16]bool{},
		}},
		{"insufficient capability", &TestingContext{
			SigVerified: true, AgentIDOk: true, SessionValid: true,
			AuthorizedOk: true, CapabilitiesOk: false, TranscriptValid: true,
			NegotiatedTypes: map[uint16]bool{}, KnownTypes: map[uint16]bool{},
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New(tt.ctx, nil)
			extBytes := encodeExt(0x0001, false, []byte{0x01})
			data := makeDataFrame([]byte{0x01}, extBytes)
			_, err := p.Process(data)
			if err == nil {
				t.Fatalf("should fail for: %s", tt.name)
			}
			pe := err.(*PipelineError)
			if pe.ExtensionCallbacksInvoked() {
				t.Errorf("callback should not be invoked for: %s (phase: %s)",
					tt.name, pe.Phase)
			}
		})
	}
}
