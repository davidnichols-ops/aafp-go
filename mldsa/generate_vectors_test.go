// Package mldsa — Go test vector generator for cross-verification (A-10).
//
// This file generates ML-DSA-65 test vectors using the Go implementation
// with deterministic key generation and deterministic signing.
// The same vectors can be verified by the Rust implementation.

package mldsa

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type goTestVector struct {
	ID             string `json:"id"`
	Seed           string `json:"seed"`
	MessageHex     string `json:"message_hex"`
	ContextHex     string `json:"context_hex"`
	PublicKeyHex   string `json:"public_key_hex"`
	SecretKeyHex   string `json:"secret_key_hex"`
	SignatureHex   string `json:"signature_hex"`
	ExpectedVerify bool   `json:"expected_verify"`
	Description    string `json:"description"`
}

func makeGoVector(id, seedHex, message, description string) goTestVector {
	seed, _ := hex.DecodeString(seedHex)
	pk, sk, err := KeypairFromSeed(seed)
	if err != nil {
		panic(err)
	}
	sig, err := SignDeterministic(sk, []byte(message))
	if err != nil {
		panic(err)
	}
	verify := Verify(pk, []byte(message), sig)
	return goTestVector{
		ID:             id,
		Seed:           seedHex,
		MessageHex:     hex.EncodeToString([]byte(message)),
		ContextHex:     "",
		PublicKeyHex:   hex.EncodeToString(pk.Bytes()),
		SecretKeyHex:   hex.EncodeToString(sk.Bytes()),
		SignatureHex:   hex.EncodeToString(sig.Bytes()),
		ExpectedVerify: verify,
		Description:    description,
	}
}

// TestGenerateGoVectors generates test vectors using the Go implementation
// and writes them to test-vectors/mldsa65/go_vectors.json.
// These vectors are then verified by the Rust implementation.
func TestGenerateGoVectors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping vector generation in short mode")
	}

	vectors := []goTestVector{
		makeGoVector("go_valid_basic",
			"4242424242424242424242424242424242424242424242424242424242424242",
			"post-quantum aafp handshake",
			"Go: Valid signature over a basic message"),
		makeGoVector("go_valid_empty_message",
			"4242424242424242424242424242424242424242424242424242424242424242",
			"",
			"Go: Valid signature over an empty message"),
		makeGoVector("go_valid_handshake_input",
			"4242424242424242424242424242424242424242424242424242424242424242",
			"aafp-v1-handshake"+string(make([]byte, 32)),
			"Go: Valid signature over domain_separator || transcript_hash"),
		makeGoVector("go_valid_different_seed",
			"9999999999999999999999999999999999999999999999999999999999999999",
			"another test message",
			"Go: Valid signature with a different key seed"),
		makeGoVector("go_valid_zero_seed",
			"0000000000000000000000000000000000000000000000000000000000000000",
			"zero seed test",
			"Go: Valid signature with all-zeros seed"),
		makeGoVector("go_valid_ff_seed",
			"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"ff seed test",
			"Go: Valid signature with all-FF seed"),
		makeGoVector("go_valid_single_byte",
			"4242424242424242424242424242424242424242424242424242424242424242",
			string([]byte{0x00}),
			"Go: Valid signature over a single byte message"),
		makeGoVector("go_valid_zero_message",
			"4242424242424242424242424242424242424242424242424242424242424242",
			string(make([]byte, 32)),
			"Go: Valid signature over all-zeros message (32 bytes)"),
		makeGoVector("go_valid_ff_message",
			"4242424242424242424242424242424242424242424242424242424242424242",
			string(make([]byte, 32)), // will be filled with 0xFF below
			"Go: Valid signature over all-FF message (32 bytes)"),
	}

	// Fix the all-FF message vector.
	ffMsg := make([]byte, 32)
	for i := range ffMsg {
		ffMsg[i] = 0xFF
	}
	vectors[8] = makeGoVector("go_valid_ff_message",
		"4242424242424242424242424242424242424242424242424242424242424242",
		string(ffMsg),
		"Go: Valid signature over all-FF message (32 bytes)")

	// Add randomized vectors.
	for i := 0; i < 5; i++ {
		seed := make([]byte, 32)
		seed[0] = byte(i + 1)
		for j := 1; j < 32; j++ {
			seed[j] = seed[0]
		}
		msg := "randomized test message #" + string(rune('0'+i))
		vectors = append(vectors, makeGoVector(
			"go_valid_random_"+string(rune('0'+i)),
			hex.EncodeToString(seed),
			msg,
			"Go: Valid signature over randomized message",
		))
	}

	// Add invalid vectors.
	{
		// Altered message.
		seed := make([]byte, 32)
		for i := range seed {
			seed[i] = 0x42
		}
		pk, sk, _ := KeypairFromSeed(seed)
		sig, _ := SignDeterministic(sk, []byte("original message"))
		vectors = append(vectors, goTestVector{
			ID:             "go_invalid_altered_message",
			Seed:           hex.EncodeToString(seed),
			MessageHex:     hex.EncodeToString([]byte("altered message")),
			ContextHex:     "",
			PublicKeyHex:   hex.EncodeToString(pk.Bytes()),
			SecretKeyHex:   hex.EncodeToString(sk.Bytes()),
			SignatureHex:   hex.EncodeToString(sig.Bytes()),
			ExpectedVerify: Verify(pk, []byte("altered message"), sig),
			Description:    "Go: Invalid: signature over 'original message', verified against 'altered message'",
		})
	}

	// Write to file.
	paths := []string{
		"../../../../test-vectors/mldsa65/go_vectors.json",
		"../../../test-vectors/mldsa65/go_vectors.json",
	}
	var writePath string
	for _, p := range paths {
		abs, _ := filepath.Abs(p)
		if _, err := os.Stat(filepath.Dir(abs)); err == nil {
			writePath = abs
			break
		}
	}
	if writePath == "" {
		t.Skip("could not find test-vectors directory")
	}

	data, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(writePath, data, 0644); err != nil {
		t.Fatal(err)
	}
	t.Logf("Generated %d Go vectors at %s", len(vectors), writePath)
}
