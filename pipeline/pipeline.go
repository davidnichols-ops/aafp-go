// Package pipeline implements the normative frame processing pipeline
// defined in RFC-0002 §6.5 (Rev 6 A-7).
//
// This package implements the explicit 20-phase frame processing pipeline.
// Each phase is a separate method that returns a typed error. The phases
// MUST be executed in the exact order specified.
//
// # Security Invariant
//
// Extension semantics MUST NOT execute before successful authentication
// and authorization. The pipeline enforces this by structurally
// separating the phases: extension callbacks are only invoked in Phase
// 18, after all authentication and authorization phases (9-14) have
// succeeded.
package pipeline

import (
	"encoding/binary"
	"fmt"
	"strings"

	"aafp-go/cbor"
	"aafp-go/errors"
	"aafp-go/frame"
	"aafp-go/frameext"
)

// PipelinePhase identifies the phase at which a pipeline error occurred.
type PipelinePhase int

const (
	Phase1ValidateHeader PipelinePhase = iota + 1
	Phase2ValidateLengths
	Phase3RejectOversized
	Phase4ReadPayload
	Phase5ReadExtensions
	Phase6DecodeCbor
	Phase7RejectDuplicateKeys
	Phase8RejectNonCanonical
	Phase9ValidateTranscript
	Phase10VerifySignatures
	Phase11VerifyAgentId
	Phase12VerifySessionState
	Phase13VerifyAuthorization
	Phase14VerifyCapabilities
	Phase15DecodeExtensions
	Phase16CheckUnknownCritical
	Phase17CheckNonNegotiated
	Phase18ProcessExtensionSemantics
	Phase19ValidateFinalState
	Phase20DeliverToUpperLayer
)

// Name returns the human-readable phase name (matches RFC §6.5.1).
func (p PipelinePhase) Name() string {
	switch p {
	case Phase1ValidateHeader:
		return "validate_frame_header"
	case Phase2ValidateLengths:
		return "validate_lengths"
	case Phase3RejectOversized:
		return "reject_oversized_before_allocation"
	case Phase4ReadPayload:
		return "read_payload"
	case Phase5ReadExtensions:
		return "read_extensions"
	case Phase6DecodeCbor:
		return "decode_canonical_cbor"
	case Phase7RejectDuplicateKeys:
		return "reject_duplicate_cbor_keys"
	case Phase8RejectNonCanonical:
		return "reject_non_canonical_cbor"
	case Phase9ValidateTranscript:
		return "validate_transcript_state"
	case Phase10VerifySignatures:
		return "verify_signatures"
	case Phase11VerifyAgentId:
		return "verify_agent_id"
	case Phase12VerifySessionState:
		return "verify_session_state"
	case Phase13VerifyAuthorization:
		return "verify_authorization"
	case Phase14VerifyCapabilities:
		return "verify_required_capabilities"
	case Phase15DecodeExtensions:
		return "decode_extensions"
	case Phase16CheckUnknownCritical:
		return "check_unknown_critical_extensions"
	case Phase17CheckNonNegotiated:
		return "check_non_negotiated_extensions"
	case Phase18ProcessExtensionSemantics:
		return "process_extension_semantics"
	case Phase19ValidateFinalState:
		return "validate_final_state"
	case Phase20DeliverToUpperLayer:
		return "deliver_to_upper_layer"
	default:
		return fmt.Sprintf("Phase(%d)", int(p))
	}
}

// Number returns the phase number (1-20).
func (p PipelinePhase) Number() int { return int(p) }

// IsPreAuthentication returns true if the phase is in the pre-authentication
// group (1-14). Extension callbacks MUST NOT execute if the failure is in
// this group.
func (p PipelinePhase) IsPreAuthentication() bool { return p.Number() <= 14 }

// IsAuthentication returns true if the phase is in the authentication group (9-14).
func (p PipelinePhase) IsAuthentication() bool { return p.Number() >= 9 && p.Number() <= 14 }

// IsExtensionProcessing returns true if the phase is in the extension
// processing group (15-18).
func (p PipelinePhase) IsExtensionProcessing() bool {
	return p.Number() >= 15 && p.Number() <= 18
}

func (p PipelinePhase) String() string {
	return fmt.Sprintf("Phase %d (%s)", p.Number(), p.Name())
}

// PipelineError is returned by the frame processing pipeline.
type PipelineError struct {
	Phase     PipelinePhase
	ErrorCode uint32
	Fatal     bool
	Message   string
}

func (e *PipelineError) Error() string {
	fatalStr := "non-fatal"
	if e.Fatal {
		fatalStr = "fatal"
	}
	return fmt.Sprintf("pipeline error at %s (code %d, %s): %s",
		e.Phase, e.ErrorCode, fatalStr, e.Message)
}

// ExtensionCallbacksInvoked returns true if extension callbacks were invoked
// before the error. This is only true for errors in Phase 18.
func (e *PipelineError) ExtensionCallbacksInvoked() bool {
	return e.Phase == Phase18ProcessExtensionSemantics
}

// NewPipelineError creates a new pipeline error.
func NewPipelineError(phase PipelinePhase, code uint32, fatal bool, msg string) *PipelineError {
	return &PipelineError{
		Phase:     phase,
		ErrorCode: code,
		Fatal:     fatal,
		Message:   msg,
	}
}

// PipelineContext provides authentication and authorization information
// to the pipeline.
type PipelineContext interface {
	// SignatureVerified returns true if the peer's signature has been verified.
	SignatureVerified() bool
	// AgentIDVerified returns true if the peer's AgentId matches the claimed identity.
	AgentIDVerified() bool
	// SessionStateValid returns true if the session is in the correct state.
	SessionStateValid(frameType byte) bool
	// Authorized returns true if the peer is authorized for this frame type.
	Authorized(frameType byte) bool
	// CapabilitiesSufficient returns true if the peer has required capabilities.
	CapabilitiesSufficient(frameType byte) bool
	// TranscriptStateValid returns true if the transcript state is valid.
	TranscriptStateValid() bool
	// NegotiatedExtensionTypes returns the set of negotiated extension types.
	NegotiatedExtensionTypes() map[uint16]bool
	// KnownExtensionTypes returns the set of known extension types.
	KnownExtensionTypes() map[uint16]bool
}

// TestingContext is a simple context for testing that allows controlling
// each phase's outcome.
type TestingContext struct {
	SigVerified             bool
	AgentIDOk               bool
	SessionValid            bool
	AuthorizedOk            bool
	CapabilitiesOk          bool
	TranscriptValid         bool
	NegotiatedTypes         map[uint16]bool
	KnownTypes              map[uint16]bool
}

// DefaultTestingContext returns a TestingContext with all checks passing.
func DefaultTestingContext() *TestingContext {
	return &TestingContext{
		SigVerified:     true,
		AgentIDOk:       true,
		SessionValid:    true,
		AuthorizedOk:    true,
		CapabilitiesOk:  true,
		TranscriptValid: true,
		NegotiatedTypes: make(map[uint16]bool),
		KnownTypes:      make(map[uint16]bool),
	}
}

func (c *TestingContext) SignatureVerified() bool       { return c.SigVerified }
func (c *TestingContext) AgentIDVerified() bool         { return c.AgentIDOk }
func (c *TestingContext) SessionStateValid(_ byte) bool { return c.SessionValid }
func (c *TestingContext) Authorized(_ byte) bool        { return c.AuthorizedOk }
func (c *TestingContext) CapabilitiesSufficient(_ byte) bool {
	return c.CapabilitiesOk
}
func (c *TestingContext) TranscriptStateValid() bool          { return c.TranscriptValid }
func (c *TestingContext) NegotiatedExtensionTypes() map[uint16]bool { return c.NegotiatedTypes }
func (c *TestingContext) KnownExtensionTypes() map[uint16]bool      { return c.KnownTypes }

// ExtensionCallback is a callback for processing extension semantics.
// Callbacks are only invoked in Phase 18.
type ExtensionCallback interface {
	// ExtensionType returns the extension type this callback handles.
	ExtensionType() uint16
	// Process processes the extension data. Called only after all
	// authentication and authorization phases have succeeded.
	Process(data []byte) error
}

// ProcessedFrame is the result of successfully processing a frame.
type ProcessedFrame struct {
	Frame                    frame.Frame
	Extensions               []frameext.Extension
	ExtensionCallbackCount   int
	ExtensionsIgnored        int
}

// FrameProcessingPipeline executes the 20-phase pipeline in order.
type FrameProcessingPipeline struct {
	ctx       PipelineContext
	callbacks []ExtensionCallback
}

// New creates a new pipeline with the given context and callbacks.
func New(ctx PipelineContext, callbacks []ExtensionCallback) *FrameProcessingPipeline {
	return &FrameProcessingPipeline{ctx: ctx, callbacks: callbacks}
}

// Process runs the full 20-phase pipeline on a raw frame byte buffer.
func (p *FrameProcessingPipeline) Process(data []byte) (*ProcessedFrame, error) {
	// Phase 1: validate_frame_header
	header, err := p.validateFrameHeader(data)
	if err != nil {
		return nil, err
	}

	// Phase 2: validate_lengths
	if err := p.validateLengths(header); err != nil {
		return nil, err
	}

	// Phase 3: reject_oversized_before_allocation
	if err := p.rejectOversizedBeforeAllocation(header); err != nil {
		return nil, err
	}

	// Phase 4-5: read_payload + read_extensions (via frame.Decode)
	f, _, err := p.readFrame(data)
	if err != nil {
		return nil, err
	}

	// Phase 6-8: CBOR validation
	if err := p.validateCbor(f); err != nil {
		return nil, err
	}

	// Phase 9: validate_transcript_state
	if err := p.validateTranscriptState(f); err != nil {
		return nil, err
	}

	// Phase 10: verify_signatures
	if err := p.verifySignatures(f); err != nil {
		return nil, err
	}

	// Phase 11: verify_agent_id
	if err := p.verifyAgentId(f); err != nil {
		return nil, err
	}

	// Phase 12: verify_session_state
	if err := p.verifySessionState(f); err != nil {
		return nil, err
	}

	// Phase 13: verify_authorization
	if err := p.verifyAuthorization(f); err != nil {
		return nil, err
	}

	// Phase 14: verify_required_capabilities
	if err := p.verifyRequiredCapabilities(f); err != nil {
		return nil, err
	}

	// ═══════════════════════════════════════════════════
	// ║ AUTHENTICATION AND AUTHORIZATION COMPLETE        ║
	// ║ Extension semantics MAY now execute.              ║
	// ═══════════════════════════════════════════════════

	// Phase 15: decode_extensions
	parsedExts, err := p.decodeExtensions(f)
	if err != nil {
		return nil, err
	}

	// Phase 16: check_unknown_critical_extensions
	if err := p.checkUnknownCritical(parsedExts); err != nil {
		return nil, err
	}

	// Phase 17: check_non_negotiated_extensions
	if err := p.checkNonNegotiated(parsedExts); err != nil {
		return nil, err
	}

	// Phase 18: process_extension_semantics
	callbackCount, ignoredCount, err := p.processExtensionSemantics(parsedExts)
	if err != nil {
		return nil, err
	}

	// Phase 19: validate_final_state
	if err := p.validateFinalState(f); err != nil {
		return nil, err
	}

	// Phase 20: deliver_to_upper_layer (implicit — caller receives result)

	return &ProcessedFrame{
		Frame:                  *f,
		Extensions:             parsedExts,
		ExtensionCallbackCount: callbackCount,
		ExtensionsIgnored:      ignoredCount,
	}, nil
}

// === Phase implementations ===

// frameHeader is the parsed frame header.
type frameHeader struct {
	Version    byte
	FrameType  byte
	Flags      byte
	Reserved   byte
	StreamID   uint64
	PayloadLen int
	ExtLen     int
}

// Phase 1: validate_frame_header
func (p *FrameProcessingPipeline) validateFrameHeader(data []byte) (*frameHeader, error) {
	if len(data) < frame.HeaderSize {
		return nil, NewPipelineError(
			Phase1ValidateHeader,
			errors.MalformedFrame,
			true,
			fmt.Sprintf("incomplete header: need %d bytes, have %d", frame.HeaderSize, len(data)),
		)
	}

	version := data[0]
	if version != frame.Version {
		return nil, NewPipelineError(
			Phase1ValidateHeader,
			errors.InvalidVersion,
			true,
			fmt.Sprintf("invalid version: %d (expected %d)", version, frame.Version),
		)
	}

	reserved := data[3]
	if reserved != 0 {
		return nil, NewPipelineError(
			Phase1ValidateHeader,
			errors.ReservedFieldNonzero,
			true,
			fmt.Sprintf("reserved field is non-zero: 0x%02X", reserved),
		)
	}

	streamID := binary.BigEndian.Uint64(data[4:12])
	payloadLen := int(binary.BigEndian.Uint64(data[12:20]))
	extLen := int(binary.BigEndian.Uint64(data[20:28]))

	return &frameHeader{
		Version:    data[0],
		FrameType:  data[1],
		Flags:      data[2],
		Reserved:   data[3],
		StreamID:   streamID,
		PayloadLen: payloadLen,
		ExtLen:     extLen,
	}, nil
}

// Phase 2: validate_lengths
func (p *FrameProcessingPipeline) validateLengths(h *frameHeader) error {
	if h.PayloadLen > frame.MaxPayloadSize {
		return NewPipelineError(
			Phase2ValidateLengths,
			errors.FrameTooLarge,
			false,
			fmt.Sprintf("payload too large: %d bytes (max %d)", h.PayloadLen, frame.MaxPayloadSize),
		)
	}
	if h.ExtLen > frame.MaxExtensionSize {
		return NewPipelineError(
			Phase2ValidateLengths,
			errors.FrameTooLarge,
			false,
			fmt.Sprintf("extension too large: %d bytes (max %d)", h.ExtLen, frame.MaxExtensionSize),
		)
	}
	return nil
}

// Phase 3: reject_oversized_before_allocation
func (p *FrameProcessingPipeline) rejectOversizedBeforeAllocation(h *frameHeader) error {
	if h.PayloadLen > frame.MaxPayloadSize {
		return NewPipelineError(
			Phase3RejectOversized,
			errors.FrameTooLarge,
			false,
			"rejected before allocation: payload too large",
		)
	}
	if h.ExtLen > frame.MaxExtensionSize {
		return NewPipelineError(
			Phase3RejectOversized,
			errors.FrameTooLarge,
			false,
			"rejected before allocation: extension too large",
		)
	}
	return nil
}

// Phase 4-5: read_frame (payload + extensions)
func (p *FrameProcessingPipeline) readFrame(data []byte) (*frame.Frame, int, error) {
	f, consumed, err := frame.Decode(data)
	if err != nil {
		// Map frame errors to pipeline errors based on error message
		msg := err.Error()
		code := errors.MalformedFrame
		fatal := true
		// Check for known error patterns
		if strings.Contains(msg, "payload too large") || strings.Contains(msg, "extension section too large") {
			code = errors.FrameTooLarge
			fatal = false
		} else if strings.Contains(msg, "invalid version") {
			code = errors.InvalidVersion
		} else if strings.Contains(msg, "unknown critical frame type") {
			code = errors.UnknownCriticalFrameType
		}
		return nil, 0, NewPipelineError(Phase4ReadPayload, uint32(code), fatal, msg)
	}
	return f, consumed, nil
}

// Phase 6-8: validate CBOR for CBOR-bearing frame types
func (p *FrameProcessingPipeline) validateCbor(f *frame.Frame) error {
	switch f.FrameType {
	case frame.TypeData, frame.TypePing, frame.TypePong:
		// Opaque payload — skip CBOR validation
		return nil
	case frame.TypeHandshake, frame.TypeRPCRequest, frame.TypeRPCResponse,
		frame.TypeClose, frame.TypeError_:
		if len(f.Payload) == 0 {
			return nil
		}
		// The cbor package enforces canonical encoding on decode
		// We attempt a decode to validate
		// If it fails, it's non-canonical or malformed
		if err := cbor.CheckCanonical(f.Payload); err != nil {
			return NewPipelineError(
				Phase6DecodeCbor,
				errors.SerializationError,
				true,
				fmt.Sprintf("CBOR decode error: %v", err),
			)
		}
		return nil
	default:
		return nil
	}
}

// Phase 9: validate_transcript_state
func (p *FrameProcessingPipeline) validateTranscriptState(f *frame.Frame) error {
	if f.FrameType == frame.TypeHandshake {
		if !p.ctx.TranscriptStateValid() {
			return NewPipelineError(
				Phase9ValidateTranscript,
				errors.HandshakeFailed,
				true,
				"transcript state invalid for handshake frame",
			)
		}
	}
	return nil
}

// Phase 10: verify_signatures
func (p *FrameProcessingPipeline) verifySignatures(_ *frame.Frame) error {
	if !p.ctx.SignatureVerified() {
		return NewPipelineError(
			Phase10VerifySignatures,
			errors.InvalidSignature,
			true,
			"signature verification failed",
		)
	}
	return nil
}

// Phase 11: verify_agent_id
func (p *FrameProcessingPipeline) verifyAgentId(_ *frame.Frame) error {
	if !p.ctx.AgentIDVerified() {
		return NewPipelineError(
			Phase11VerifyAgentId,
			errors.InvalidAgentId,
			true,
			"agent ID does not match public key hash",
		)
	}
	return nil
}

// Phase 12: verify_session_state
func (p *FrameProcessingPipeline) verifySessionState(f *frame.Frame) error {
	if !p.ctx.SessionStateValid(f.FrameType) {
		return NewPipelineError(
			Phase12VerifySessionState,
			errors.ProtocolViolation,
			true,
			"session state invalid for this frame type",
		)
	}
	return nil
}

// Phase 13: verify_authorization
func (p *FrameProcessingPipeline) verifyAuthorization(f *frame.Frame) error {
	if !p.ctx.Authorized(f.FrameType) {
		return NewPipelineError(
			Phase13VerifyAuthorization,
			errors.Unauthorized,
			true,
			"peer not authorized for this action",
		)
	}
	return nil
}

// Phase 14: verify_required_capabilities
func (p *FrameProcessingPipeline) verifyRequiredCapabilities(f *frame.Frame) error {
	if !p.ctx.CapabilitiesSufficient(f.FrameType) {
		return NewPipelineError(
			Phase14VerifyCapabilities,
			errors.InsufficientCapability,
			true,
			"peer lacks required capabilities",
		)
	}
	return nil
}

// Phase 15: decode_extensions
func (p *FrameProcessingPipeline) decodeExtensions(f *frame.Frame) ([]frameext.Extension, error) {
	if len(f.Extensions) == 0 {
		return nil, nil
	}

	// Handshake frames MUST NOT carry frame extensions
	if f.FrameType == frame.TypeHandshake {
		return nil, NewPipelineError(
			Phase15DecodeExtensions,
			errors.ProtocolViolation,
			true,
			"HANDSHAKE frames MUST NOT carry frame extensions",
		)
	}

	exts, err := frameext.Decode(f.Extensions)
	if err != nil {
		return nil, NewPipelineError(
			Phase15DecodeExtensions,
			errors.MalformedFrame,
			true,
			fmt.Sprintf("extension decode error: %v", err),
		)
	}
	return exts, nil
}

// Phase 16: check_unknown_critical_extensions
func (p *FrameProcessingPipeline) checkUnknownCritical(exts []frameext.Extension) error {
	known := p.ctx.KnownExtensionTypes()
	for _, ext := range exts {
		if ext.Critical && !known[ext.ExtType] {
			return NewPipelineError(
				Phase16CheckUnknownCritical,
				errors.UnknownCriticalExtension,
				true,
				fmt.Sprintf("unknown critical extension: 0x%04X", ext.ExtType),
			)
		}
	}
	return nil
}

// Phase 17: check_non_negotiated_extensions
func (p *FrameProcessingPipeline) checkNonNegotiated(exts []frameext.Extension) error {
	negotiated := p.ctx.NegotiatedExtensionTypes()
	known := p.ctx.KnownExtensionTypes()
	for _, ext := range exts {
		if !negotiated[ext.ExtType] {
			// Unknown non-critical: will be silently ignored in Phase 18
			// Known but non-negotiated: error
			if known[ext.ExtType] {
				return NewPipelineError(
					Phase17CheckNonNegotiated,
					errors.InvalidFlags,
					true,
					fmt.Sprintf("non-negotiated extension: 0x%04X", ext.ExtType),
				)
			}
		}
	}
	return nil
}

// Phase 18: process_extension_semantics
func (p *FrameProcessingPipeline) processExtensionSemantics(
	exts []frameext.Extension,
) (int, int, error) {
	callbackCount := 0
	ignoredCount := 0
	negotiated := p.ctx.NegotiatedExtensionTypes()

	for _, ext := range exts {
		if !negotiated[ext.ExtType] {
			// Unknown non-critical extension — silently ignore
			ignoredCount++
			continue
		}

		// Find the callback for this extension type
		var cb ExtensionCallback
		for _, c := range p.callbacks {
			if c.ExtensionType() == ext.ExtType {
				cb = c
				break
			}
		}

		if cb != nil {
			if err := cb.Process(ext.Data); err != nil {
				return callbackCount, ignoredCount, NewPipelineError(
					Phase18ProcessExtensionSemantics,
					errors.ProtocolViolation,
					true,
					fmt.Sprintf("extension callback error: %v", err),
				)
			}
			callbackCount++
		} else {
			// Known and negotiated but no callback registered — skip
			ignoredCount++
		}
	}

	return callbackCount, ignoredCount, nil
}

// Phase 19: validate_final_state
func (p *FrameProcessingPipeline) validateFinalState(_ *frame.Frame) error {
	// Hook for application to verify state transitions
	return nil
}
