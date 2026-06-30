// Package mldsa — differential testing (A-10 Phase 4).
//
// Generates 10,000 deterministic traces and verifies them.
// Also verifies Rust-generated traces in Go.

package mldsa

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

type diffTrace struct {
	SeedHex      string `json:"seed_hex"`
	MessageHex   string `json:"message_hex"`
	PublicKeyHex string `json:"public_key_hex"`
	SignatureHex string `json:"signature_hex"`
	VerifyResult bool   `json:"verify_result"`
}

// TestDifferential10KGenerateAndVerify generates 10K deterministic traces
// in Go, self-verifies them, and writes them to a file for Rust verification.
// Only writes a subset (100 traces) to keep the file size manageable.
func TestDifferential10KGenerateAndVerify(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 10K differential in short mode")
	}

	count := 10_000
	traces := make([]diffTrace, count)
	exportTraces := make([]diffTrace, 0, 100)

	for i := 0; i < count; i++ {
		// Deterministic seed from index.
		seed := make([]byte, 32)
		seed[0] = byte(i >> 56)
		seed[1] = byte(i >> 48)
		seed[2] = byte(i >> 40)
		seed[3] = byte(i >> 32)
		seed[4] = byte(i >> 24)
		seed[5] = byte(i >> 16)
		seed[6] = byte(i >> 8)
		seed[7] = byte(i)

		// Deterministic message from index.
		msg := fmt.Appendf(nil, "differential test message #%d", i)

		pk, sk, err := KeypairFromSeed(seed)
		if err != nil {
			t.Fatalf("KeypairFromSeed(%d): %v", i, err)
		}
		sig, err := SignDeterministic(sk, msg)
		if err != nil {
			t.Fatalf("SignDeterministic(%d): %v", i, err)
		}
		verify := Verify(pk, msg, sig)
		if !verify {
			t.Fatalf("trace %d: self-verification failed", i)
		}

		traces[i] = diffTrace{
			SeedHex:      hex.EncodeToString(seed),
			MessageHex:   hex.EncodeToString(msg),
			PublicKeyHex: hex.EncodeToString(pk.Bytes()),
			SignatureHex: hex.EncodeToString(sig.Bytes()),
			VerifyResult: verify,
		}

		// Export only every 100th trace to keep file size manageable.
		if i%100 == 0 {
			exportTraces = append(exportTraces, traces[i])
		}
	}

	// Write subset to file for Rust verification.
	paths := []string{
		"../../../../test-vectors/mldsa65/go_diff_traces.json",
		"../../../test-vectors/mldsa65/go_diff_traces.json",
	}
	data, _ := json.Marshal(exportTraces)
	for _, p := range paths {
		abs, _ := filepath.Abs(p)
		if err := os.WriteFile(abs, data, 0644); err == nil {
			t.Logf("Wrote %d (of %d) Go diff traces to %s", len(exportTraces), count, abs)
			break
		}
	}
	t.Logf("Differential: %d/%d traces verified in Go", count, count)
}

// TestDifferentialVerifyRustTraces loads Rust-generated diff traces
// and verifies them in Go.
func TestDifferentialVerifyRustTraces(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	paths := []string{
		"../../../../test-vectors/mldsa65/diff_traces.json",
		"../../../test-vectors/mldsa65/diff_traces.json",
	}
	var data []byte
	var found bool
	for _, p := range paths {
		abs, _ := filepath.Abs(p)
		d, err := os.ReadFile(abs)
		if err == nil {
			data = d
			found = true
			break
		}
	}
	if !found {
		t.Skip("Rust diff traces not found — run Rust tests first")
	}

	var traces []diffTrace
	if err := json.Unmarshal(data, &traces); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if len(traces) == 0 {
		t.Fatal("no traces found")
	}

	passed := 0
	for i, tr := range traces {
		pk, err := NewPublicKey(mustHexDecode(tr.PublicKeyHex))
		if err != nil {
			t.Fatalf("trace %d: bad public key: %v", i, err)
		}
		sig, err := NewSignature(mustHexDecode(tr.SignatureHex))
		if err != nil {
			t.Fatalf("trace %d: bad signature: %v", i, err)
		}
		msg := mustHexDecode(tr.MessageHex)
		result := Verify(pk, msg, sig)
		if result != tr.VerifyResult {
			t.Errorf("trace %d: expected %v, got %v", i, tr.VerifyResult, result)
		}
		passed++
	}
	t.Logf("Differential: %d/%d Rust traces verified in Go", passed, len(traces))
}

// TestDifferentialKeygenConsistency10K verifies keygen determinism.
func TestDifferentialKeygenConsistency10K(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 10K keygen in short mode")
	}
	for i := 0; i < 10_000; i++ {
		seed := make([]byte, 32)
		seed[0] = byte(i >> 24)
		seed[1] = byte(i >> 16)
		seed[2] = byte(i >> 8)
		seed[3] = byte(i)

		pk1, _, err := KeypairFromSeed(seed)
		if err != nil {
			t.Fatalf("KeypairFromSeed(%d): %v", i, err)
		}
		pk2, _, err := KeypairFromSeed(seed)
		if err != nil {
			t.Fatalf("KeypairFromSeed(%d) (2nd): %v", i, err)
		}
		if !bytes.Equal(pk1.Bytes(), pk2.Bytes()) {
			t.Fatalf("keygen not deterministic for seed %d", i)
		}
	}
	t.Logf("Keygen consistency: 10000/10000 seeds deterministic")
}
