// Package mldsa — cross-verification matrix (A-10 Phase 3).
//
// Tests all 4 combinations from the Go side:
//   Rust→Go, Go→Go (Rust→Rust and Go→Rust are tested in Rust)

package mldsa

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestMatrixRustToGo verifies all Rust-generated vectors in Go.
func TestMatrixRustToGo(t *testing.T) {
	vectors := loadTestVectors(t)
	passed := 0
	for _, v := range vectors {
		pk := mustNewPublicKey(mustHexDecode(v.PublicKeyHex))
		sig := mustNewSignature(mustHexDecode(v.SignatureHex))
		msg := mustHexDecode(v.MessageHex)
		result := Verify(pk, msg, sig)
		if result == v.ExpectedVerify {
			passed++
		} else {
			t.Errorf("Rust→Go: %s: expected %v, got %v", v.ID, v.ExpectedVerify, result)
		}
	}
	t.Logf("Rust→Go: %d/%d passed", passed, len(vectors))
	if passed != len(vectors) {
		t.Errorf("Rust→Go: %d/%d passed", passed, len(vectors))
	}
}

// TestMatrixGoToGo verifies all Go-generated vectors in Go.
func TestMatrixGoToGo(t *testing.T) {
	vectors := loadGoVectors(t)
	passed := 0
	for _, v := range vectors {
		pk := mustNewPublicKey(mustHexDecode(v.PublicKeyHex))
		sig := mustNewSignature(mustHexDecode(v.SignatureHex))
		msg := mustHexDecode(v.MessageHex)
		result := Verify(pk, msg, sig)
		if result == v.ExpectedVerify {
			passed++
		} else {
			t.Errorf("Go→Go: %s: expected %v, got %v", v.ID, v.ExpectedVerify, result)
		}
	}
	t.Logf("Go→Go: %d/%d passed", passed, len(vectors))
	if passed != len(vectors) {
		t.Errorf("Go→Go: %d/%d passed", passed, len(vectors))
	}
}

func loadGoVectors(t *testing.T) []testVector {
	paths := []string{
		"../../../../test-vectors/mldsa65/go_vectors.json",
		"../../../test-vectors/mldsa65/go_vectors.json",
	}
	for _, p := range paths {
		abs, _ := filepath.Abs(p)
		data, err := os.ReadFile(abs)
		if err == nil {
			var vectors []testVector
			if err := json.Unmarshal(data, &vectors); err != nil {
				t.Fatalf("failed to parse Go vectors: %v", err)
			}
			return vectors
		}
	}
	t.Skip("Go vectors not found — run TestGenerateGoVectors first")
	return nil
}

func mustHexDecode(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func mustNewPublicKey(b []byte) *PublicKey {
	pk, err := NewPublicKey(b)
	if err != nil {
		panic(err)
	}
	return pk
}

func mustNewSignature(b []byte) *Signature {
	sig, err := NewSignature(b)
	if err != nil {
		panic(err)
	}
	return sig
}

// TestMatrixSummary prints a summary of all 4 combinations.
func TestMatrixSummary(t *testing.T) {
	rustVectors := loadTestVectors(t)
	goVectors := loadGoVectors(t)

	// Rust→Go
	rgPass := 0
	for _, v := range rustVectors {
		pk := mustNewPublicKey(mustHexDecode(v.PublicKeyHex))
		sig := mustNewSignature(mustHexDecode(v.SignatureHex))
		msg := mustHexDecode(v.MessageHex)
		if Verify(pk, msg, sig) == v.ExpectedVerify {
			rgPass++
		}
	}

	// Go→Go
	ggPass := 0
	for _, v := range goVectors {
		pk := mustNewPublicKey(mustHexDecode(v.PublicKeyHex))
		sig := mustNewSignature(mustHexDecode(v.SignatureHex))
		msg := mustHexDecode(v.MessageHex)
		if Verify(pk, msg, sig) == v.ExpectedVerify {
			ggPass++
		}
	}

	t.Logf("┌────────────────────────────────────────────┐")
	t.Logf("│  Cross-Verification Matrix (Go side)       │")
	t.Logf("├──────────────┬──────────┬───────────────────┤")
	t.Logf("│ Sign → Verify│ Pass/Total│ Status           │")
	t.Logf("├──────────────┼──────────┼───────────────────┤")
	t.Logf("│ Rust → Go    │ %d/%d  │ %s │",
		rgPass, len(rustVectors),
		statusStr(rgPass == len(rustVectors)))
	t.Logf("│ Go   → Go    │ %d/%d  │ %s │",
		ggPass, len(goVectors),
		statusStr(ggPass == len(goVectors)))
	t.Logf("│ Rust → Rust  │ (see Rust)│ (verified in Rust)│")
	t.Logf("│ Go   → Rust  │ (see Rust)│ (verified in Rust)│")
	t.Logf("└──────────────┴──────────┴───────────────────┘")

	if rgPass != len(rustVectors) {
		t.Errorf("Rust→Go: %d/%d passed", rgPass, len(rustVectors))
	}
	if ggPass != len(goVectors) {
		t.Errorf("Go→Go: %d/%d passed", ggPass, len(goVectors))
	}
}

func statusStr(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}
