package pipeline

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// PipelineContextConfig matches the Rust struct for differential testing.
type PipelineContextConfig struct {
	SignatureVerified      bool   `json:"signature_verified"`
	AgentIDVerified        bool   `json:"agent_id_verified"`
	SessionValid           bool   `json:"session_valid"`
	Authorized             bool   `json:"authorized"`
	CapabilitiesSufficient bool   `json:"capabilities_sufficient"`
	TranscriptValid        bool   `json:"transcript_valid"`
	KnownTypes             []uint16 `json:"known_types"`
	NegotiatedTypes        []uint16 `json:"negotiated_types"`
}

type PipelineTestVector struct {
	Description              string                  `json:"description"`
	FrameHex                 string                  `json:"frame_hex"`
	Context                  PipelineContextConfig   `json:"context"`
	ExpectedSuccess          bool                    `json:"expected_success"`
	ExpectedPhase            *int                    `json:"expected_phase"`
	ExpectedErrorCode        *uint32                 `json:"expected_error_code"`
	ExpectedFatal            *bool                   `json:"expected_fatal"`
	ExpectedCallbackCount    int                     `json:"expected_callback_count"`
	ExpectedExtensionsIgnored int                    `json:"expected_extensions_ignored"`
}

type PipelineTestVectors struct {
	Vectors []PipelineTestVector `json:"vectors"`
}

// noopCallback is a callback that does nothing (matches Rust's NoopCallback).
type noopCallback struct{}

func (noopCallback) ExtensionType() uint16     { return 0x0001 }
func (noopCallback) Process(_ []byte) error     { return nil }

func toTestingContext(cfg PipelineContextConfig) *TestingContext {
	ctx := &TestingContext{
		SigVerified:     cfg.SignatureVerified,
		AgentIDOk:       cfg.AgentIDVerified,
		SessionValid:    cfg.SessionValid,
		AuthorizedOk:    cfg.Authorized,
		CapabilitiesOk:  cfg.CapabilitiesSufficient,
		TranscriptValid: cfg.TranscriptValid,
		NegotiatedTypes: make(map[uint16]bool),
		KnownTypes:      make(map[uint16]bool),
	}
	for _, t := range cfg.KnownTypes {
		ctx.KnownTypes[t] = true
	}
	for _, t := range cfg.NegotiatedTypes {
		ctx.NegotiatedTypes[t] = true
	}
	return ctx
}

func loadPipelineVectors(t *testing.T) *PipelineTestVectors {
	data, err := os.ReadFile("pipeline_vectors.json")
	if err != nil {
		t.Skipf("pipeline_vectors.json not found: %v", err)
	}
	var vectors PipelineTestVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("failed to parse vectors: %v", err)
	}
	return &vectors
}

// TestDifferentialPipelineVectors runs the Rust-generated pipeline test
// vectors against the Go implementation and verifies that both produce
// identical results (phase, error code, callback count).
func TestDifferentialPipelineVectors(t *testing.T) {
	vectors := loadPipelineVectors(t)
	if len(vectors.Vectors) == 0 {
		t.Skip("no test vectors found")
	}

	for _, v := range vectors.Vectors {
		t.Run(v.Description, func(t *testing.T) {
			frameData, err := hex.DecodeString(v.FrameHex)
			if err != nil {
				t.Fatalf("failed to decode frame hex: %v", err)
			}

			ctx := toTestingContext(v.Context)
			callbacks := []ExtensionCallback{noopCallback{}}
			p := New(ctx, callbacks)

			result, err := p.Process(frameData)

			if v.ExpectedSuccess {
				if err != nil {
					t.Fatalf("expected success, got error: %v", err)
				}
				if result.ExtensionCallbackCount != v.ExpectedCallbackCount {
					t.Errorf("callback count: expected %d, got %d",
						v.ExpectedCallbackCount, result.ExtensionCallbackCount)
				}
				if result.ExtensionsIgnored != v.ExpectedExtensionsIgnored {
					t.Errorf("extensions ignored: expected %d, got %d",
						v.ExpectedExtensionsIgnored, result.ExtensionsIgnored)
				}
			} else {
				if err == nil {
					t.Fatal("expected failure, got success")
				}
				pe, ok := err.(*PipelineError)
				if !ok {
					t.Fatalf("expected *PipelineError, got %T: %v", err, err)
				}

				if v.ExpectedPhase != nil {
					if pe.Phase.Number() != *v.ExpectedPhase {
						t.Errorf("phase: expected %d, got %d (%s)",
							*v.ExpectedPhase, pe.Phase.Number(), pe.Phase)
					}
				}

				if v.ExpectedErrorCode != nil {
					if pe.ErrorCode != *v.ExpectedErrorCode {
						t.Errorf("error code: expected %d, got %d",
							*v.ExpectedErrorCode, pe.ErrorCode)
					}
				}

				if v.ExpectedFatal != nil {
					if pe.Fatal != *v.ExpectedFatal {
						t.Errorf("fatal: expected %v, got %v",
							*v.ExpectedFatal, pe.Fatal)
					}
				}

				// Security invariant: callbacks must not be invoked on failure
				if pe.ExtensionCallbacksInvoked() {
					t.Error("security violation: callbacks invoked on failure")
				}
			}
		})
	}
}
