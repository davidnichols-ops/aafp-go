// Package mldsa — RFC verification (A-10 Phase 8).
//
// Verifies conformance to RFC-0002 and RFC-0003.

package mldsa

import (
	"bytes"
	"testing"
)

// RFC-0003 §2.3: Key Algorithm Registry
func TestRFC0003KeyAlgorithmID(t *testing.T) {
	if KeyAlgorithmID != 1 {
		t.Errorf("RFC-0003 §2.3: ML-DSA-65 must be algorithm 1, got %d", KeyAlgorithmID)
	}
}

func TestRFC0003KeySizes(t *testing.T) {
	if PublicKeySize != 1952 {
		t.Errorf("RFC-0003 §2.3: public key must be 1952 bytes, got %d", PublicKeySize)
	}
	if SecretKeySize != 4032 {
		t.Errorf("RFC-0003 §2.3: secret key must be 4032 bytes, got %d", SecretKeySize)
	}
	if SignatureSize != 3309 {
		t.Errorf("RFC-0003 §2.3: signature must be 3309 bytes, got %d", SignatureSize)
	}
}

func TestRFC0003GeneratedKeySizes(t *testing.T) {
	pk, sk, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if len(pk.Bytes()) != 1952 {
		t.Errorf("public key: got %d, want 1952", len(pk.Bytes()))
	}
	if len(sk.Bytes()) != 4032 {
		t.Errorf("secret key: got %d, want 4032", len(sk.Bytes()))
	}
	sig, err := Sign(sk, []byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	if len(sig.Bytes()) != 3309 {
		t.Errorf("signature: got %d, want 3309", len(sig.Bytes()))
	}
}

// RFC-0003 §2.4: Hedged signing (default)
func TestRFC0003HedgedSigningNonDeterministic(t *testing.T) {
	_, sk, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hedged signing test message")
	sig1, err := Sign(sk, msg)
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := Sign(sk, msg)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(sig1.Bytes(), sig2.Bytes()) {
		t.Error("RFC-0003 §2.4: hedged signing must produce different signatures")
	}
}

func TestRFC0003DeterministicSigningAvailable(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, 32)
	pk, sk, err := KeypairFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("deterministic signing test")
	sig1, err := SignDeterministic(sk, msg)
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := SignDeterministic(sk, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sig1.Bytes(), sig2.Bytes()) {
		t.Error("deterministic signing must be reproducible")
	}
	if !Verify(pk, msg, sig1) {
		t.Error("deterministic signature 1 must verify")
	}
	if !Verify(pk, msg, sig2) {
		t.Error("deterministic signature 2 must verify")
	}
}

// RFC-0003 §3.5: Domain Separation
func TestRFC0003DomainSeparatorsPrefixFree(t *testing.T) {
	handshake := []byte("aafp-v1-handshake")
	record := []byte("aafp-v1-record")
	ucan := []byte("aafp-v1-ucan")

	if isPrefix(handshake, record) {
		t.Error("handshake must not be prefix of record")
	}
	if isPrefix(handshake, ucan) {
		t.Error("handshake must not be prefix of ucan")
	}
	if isPrefix(record, handshake) {
		t.Error("record must not be prefix of handshake")
	}
	if isPrefix(record, ucan) {
		t.Error("record must not be prefix of ucan")
	}
	if isPrefix(ucan, handshake) {
		t.Error("ucan must not be prefix of handshake")
	}
	if isPrefix(ucan, record) {
		t.Error("ucan must not be prefix of record")
	}
}

func isPrefix(a, b []byte) bool {
	if len(a) >= len(b) {
		return false
	}
	return bytes.Equal(b[:len(a)], a)
}

func TestRFC0003DomainSeparatorNoNul(t *testing.T) {
	ds := []byte("aafp-v1-handshake")
	for _, b := range ds {
		if b == 0 {
			t.Error("domain separator must not contain NUL bytes")
		}
	}
}

func TestRFC0003DomainSeparatorInSignatureInput(t *testing.T) {
	ds := []byte("aafp-v1-handshake") // 17 bytes
	transcriptHash := bytes.Repeat([]byte{0xab}, 32)
	sigInput := make([]byte, 0, len(ds)+len(transcriptHash))
	sigInput = append(sigInput, ds...)
	sigInput = append(sigInput, transcriptHash...)

	if len(sigInput) != 49 {
		t.Errorf("signature input: got %d, want 49", len(sigInput))
	}
	if !bytes.Equal(sigInput[:17], ds) {
		t.Error("first 17 bytes must be domain separator")
	}
	if !bytes.Equal(sigInput[17:], transcriptHash) {
		t.Error("last 32 bytes must be transcript hash")
	}

	pk, sk, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(sk, sigInput)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(pk, sigInput, sig) {
		t.Error("signature over domain_separator || transcript_hash must verify")
	}
}

// Cross-implementation consistency
func TestCrossImplEmptyContextString(t *testing.T) {
	pk, sk, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("empty context test")
	sig, err := Sign(sk, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(pk, msg, sig) {
		t.Error("empty context string must produce valid signatures")
	}
}

func TestCrossImplSeedBasedKeygenDeterministic(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, 32)
	pk1, sk1, err := KeypairFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	pk2, sk2, err := KeypairFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pk1.Bytes(), pk2.Bytes()) {
		t.Error("seed-based keygen must be deterministic (public key)")
	}
	if !bytes.Equal(sk1.Bytes(), sk2.Bytes()) {
		t.Error("seed-based keygen must be deterministic (secret key)")
	}
}

func TestRFCWireFormatCompatibility(t *testing.T) {
	pk, sk, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(sk, []byte("wire format test"))
	if err != nil {
		t.Fatal(err)
	}

	if len(pk.Bytes()) != 1952 {
		t.Errorf("wire format: public key is raw 1952 bytes, got %d", len(pk.Bytes()))
	}
	if len(sk.Bytes()) != 4032 {
		t.Errorf("wire format: secret key is raw 4032 bytes, got %d", len(sk.Bytes()))
	}
	if len(sig.Bytes()) != 3309 {
		t.Errorf("wire format: signature is raw 3309 bytes, got %d", len(sig.Bytes()))
	}

	pk2, err := NewPublicKey(pk.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := NewSignature(sig.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(pk2, []byte("wire format test"), sig2) {
		t.Error("wire format: round-trip must verify")
	}
}
