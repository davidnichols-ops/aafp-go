// Package replaycache — differential tests for RFC-0002 §6.7 (A-9).
//
// These tests load replay trace vectors from replay_vectors.json and
// execute them against the Go ReplayCache. The same vectors are
// executed against the Rust ReplayCache, ensuring both implementations
// produce identical results for the same sequence of operations.

package replaycache

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type traceStep struct {
	Op      string `json:"op"`
	AgentID string `json:"agent_id"`
	Nonce   string `json:"nonce"`
	Expect  string `json:"expect"`
}

type trace struct {
	Name  string      `json:"name"`
	Steps []traceStep `json:"steps"`
}

func hexToBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func hexToNonce(s string) []byte {
	b := hexToBytes(s)
	if len(b) != NonceSize {
		panic("nonce must be 32 bytes")
	}
	return b
}

func runTrace(t *testing.T, tr *trace) {
	c := New()
	for i, step := range tr.Steps {
		var result string
		switch step.Op {
		case "check_and_insert":
			aid := hexToBytes(step.AgentID)
			n := hexToNonce(step.Nonce)
			if err := c.CheckAndInsert(aid, n); err != nil {
				result = "replay"
			} else {
				result = "ok"
			}
		case "check":
			aid := hexToBytes(step.AgentID)
			n := hexToNonce(step.Nonce)
			if c.Check(aid, n) {
				result = "true"
			} else {
				result = "false"
			}
		case "insert":
			aid := hexToBytes(step.AgentID)
			n := hexToNonce(step.Nonce)
			c.Insert(aid, n)
			result = "ok"
		case "clear":
			c.Clear()
			result = "ok"
		default:
			t.Fatalf("trace %s step %d: unknown op: %s", tr.Name, i, step.Op)
		}
		if result != step.Expect {
			t.Errorf("trace %s step %d (%s): expected %s, got %s",
				tr.Name, i, step.Op, step.Expect, result)
		}
	}
}

func TestDifferentialReplayVectors(t *testing.T) {
	data, err := os.ReadFile("replay_vectors.json")
	if err != nil {
		t.Fatalf("failed to read vectors: %v", err)
	}
	var traces []trace
	if err := json.Unmarshal(data, &traces); err != nil {
		t.Fatalf("failed to parse vectors: %v", err)
	}
	if len(traces) == 0 {
		t.Fatal("should have at least one trace")
	}
	for i := range traces {
		t.Run(traces[i].Name, func(t *testing.T) {
			runTrace(t, &traces[i])
		})
	}
}

func TestDifferentialTraceCount(t *testing.T) {
	data, err := os.ReadFile("replay_vectors.json")
	if err != nil {
		t.Fatalf("failed to read vectors: %v", err)
	}
	var traces []trace
	if err := json.Unmarshal(data, &traces); err != nil {
		t.Fatalf("failed to parse vectors: %v", err)
	}
	if len(traces) < 15 {
		t.Fatalf("should have at least 15 differential traces, got %d", len(traces))
	}
}
