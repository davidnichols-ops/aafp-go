package closemanager

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Differential test vectors for CloseManager (RFC-0002 §6.6, A-8).
// These vectors are shared between Rust and Go to verify both
// implementations produce identical results for the same event sequences.

// CloseEventVec represents a single event in a trace vector.
type CloseEventVec struct {
	Type    string `json:"type"`
	Code    uint32 `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// CloseActionVec represents an expected action result.
type CloseActionVec struct {
	Kind             string `json:"kind"`
	Code             uint32 `json:"code,omitempty"`
	Message          string `json:"message,omitempty"`
	MessageTruncated bool   `json:"message_truncated,omitempty"`
}

// CloseTraceVector represents a complete shutdown trace.
type CloseTraceVector struct {
	Name               string           `json:"name"`
	Description        string           `json:"description"`
	Events             []CloseEventVec  `json:"events"`
	ExpectedFinalState string           `json:"expected_final_state"`
	ExpectedActions    []CloseActionVec `json:"expected_actions"`
}

// CloseTraceVectors is the top-level vector file.
type CloseTraceVectors struct {
	Description string             `json:"description"`
	Vectors     []CloseTraceVector `json:"vectors"`
}

func loadCloseVectors(t *testing.T) *CloseTraceVectors {
	path := filepath.Join("close_vectors.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read vectors: %v", err)
	}
	var v CloseTraceVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("failed to parse vectors: %v", err)
	}
	return &v
}

func applyEvent(cm *CloseManager, evt CloseEventVec) CloseAction {
	switch evt.Type {
	case "initiate_close":
		return cm.InitiateClose(evt.Code, evt.Message)
	case "on_close_received":
		return cm.OnCloseReceived(evt.Code, evt.Message)
	case "respond_close":
		return cm.RespondClose(evt.Code, evt.Message)
	case "on_timeout":
		return cm.OnTimeout()
	case "on_fatal_error":
		return cm.OnFatalErrorReceived()
	case "on_transport_reset":
		return cm.OnTransportReset()
	case "abort":
		return cm.Abort()
	default:
		return None()
	}
}

func actionKindString(a CloseAction) string {
	switch a.Kind {
	case ActionNone:
		return "none"
	case ActionSendCloseFrame:
		return "send_close_frame"
	case ActionCloseQuic:
		return "close_quic"
	default:
		return "unknown"
	}
}

func stateString(s CloseState) string {
	switch s {
	case StateOpen:
		return "Open"
	case StateLocalCloseSent:
		return "LocalCloseSent"
	case StateRemoteCloseReceived:
		return "RemoteCloseReceived"
	case StateCloseReceived:
		return "CloseReceived"
	case StateClosed:
		return "Closed"
	default:
		return "Unknown"
	}
}

func TestDifferentialCloseVectors(t *testing.T) {
	vectors := loadCloseVectors(t)
	if len(vectors.Vectors) == 0 {
		t.Fatal("no vectors loaded")
	}

	for _, v := range vectors.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			cm := New()
			var actions []CloseAction

			for _, evt := range v.Events {
				action := applyEvent(cm, evt)
				actions = append(actions, action)
			}

			// Verify final state.
			if got := stateString(cm.State()); got != v.ExpectedFinalState {
				t.Errorf("final state: got %s, want %s", got, v.ExpectedFinalState)
			}

			// Verify number of actions.
			if len(actions) != len(v.ExpectedActions) {
				t.Fatalf("action count: got %d, want %d", len(actions), len(v.ExpectedActions))
			}

			for i, expected := range v.ExpectedActions {
				got := actions[i]
				gotKind := actionKindString(got)

				if gotKind != expected.Kind {
					t.Errorf("action[%d] kind: got %s, want %s", i, gotKind, expected.Kind)
					continue
				}

				if expected.Kind == "send_close_frame" {
					if got.Code != expected.Code {
						t.Errorf("action[%d] code: got %d, want %d", i, got.Code, expected.Code)
					}
					if expected.MessageTruncated {
						if len(got.Message) > MaxCloseMessageLen {
							t.Errorf("action[%d] message not truncated: %d", i, len(got.Message))
						}
					} else if got.Message != expected.Message {
						t.Errorf("action[%d] message: got %q, want %q", i, got.Message, expected.Message)
					}
				}
			}
		})
	}
}

// TestDifferentialVectorCount verifies we have a reasonable number of vectors.
func TestDifferentialVectorCount(t *testing.T) {
	vectors := loadCloseVectors(t)
	if len(vectors.Vectors) < 15 {
		t.Errorf("expected at least 15 vectors, got %d", len(vectors.Vectors))
	}
}
