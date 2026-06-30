// Package mldsa — property testing (A-10 Phase 6).
//
// Verifies: sign(message) → verify(message) always succeeds,
// and mutating any component causes verification to fail.

package mldsa

import (
	"bytes"
	"testing"
)

// Deterministic PRNG (xorshift64*).
type prng struct {
	state uint64
}

func newPrng(seed uint64) *prng {
	return &prng{state: seed}
}

func (p *prng) nextU64() uint64 {
	x := p.state
	x ^= x << 13
	x ^= x >> 7
	x ^= x << 17
	p.state = x
	return x
}

func (p *prng) fillBytes(buf []byte) {
	for i := 0; i < len(buf); i += 8 {
		v := p.nextU64()
		for j := 0; j < 8 && i+j < len(buf); j++ {
			buf[i+j] = byte(v >> (j * 8))
		}
	}
}

func (p *prng) nextVec(n int) []byte {
	v := make([]byte, n)
	p.fillBytes(v)
	return v
}

func TestPropertySignVerifyAlwaysSucceeds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping property test in short mode")
	}
	prng := newPrng(0x1234567890ABCDEF)
	iterations := 1000

	for i := 0; i < iterations; i++ {
		seed := make([]byte, 32)
		prng.fillBytes(seed)
		pk, sk, err := KeypairFromSeed(seed)
		if err != nil {
			t.Fatalf("iteration %d: KeypairFromSeed: %v", i, err)
		}
		msgLen := int(prng.nextU64() % 256)
		msg := prng.nextVec(msgLen)
		sig, err := Sign(sk, msg)
		if err != nil {
			t.Fatalf("iteration %d: Sign: %v", i, err)
		}
		if !Verify(pk, msg, sig) {
			t.Fatalf("iteration %d: sign→verify must always succeed", i)
		}
	}
	t.Logf("Property: %d/%d sign→verify succeeded", iterations, iterations)
}

func TestPropertyMutateMessageFails(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping property test in short mode")
	}
	prng := newPrng(0xDEADBEEFCAFEBABE)
	iterations := 500

	for i := 0; i < iterations; i++ {
		seed := make([]byte, 32)
		prng.fillBytes(seed)
		pk, sk, err := KeypairFromSeed(seed)
		if err != nil {
			t.Fatal(err)
		}
		msg := prng.nextVec(32)
		sig, err := Sign(sk, msg)
		if err != nil {
			t.Fatal(err)
		}
		mutated := make([]byte, len(msg))
		copy(mutated, msg)
		bitPos := int(prng.nextU64() % 256)
		mutated[bitPos%len(mutated)] ^= byte(0x01 << (prng.nextU64() % 8))
		if Verify(pk, mutated, sig) {
			t.Fatalf("iteration %d: mutated message must fail", i)
		}
	}
	t.Logf("Property: %d/%d mutated messages correctly rejected", iterations, iterations)
}

func TestPropertyMutateSignatureFails(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping property test in short mode")
	}
	prng := newPrng(0xCAFED00DBAADF00D)
	iterations := 500

	for i := 0; i < iterations; i++ {
		seed := make([]byte, 32)
		prng.fillBytes(seed)
		pk, sk, err := KeypairFromSeed(seed)
		if err != nil {
			t.Fatal(err)
		}
		msg := prng.nextVec(32)
		sig, err := Sign(sk, msg)
		if err != nil {
			t.Fatal(err)
		}
		mutated := make([]byte, len(sig.Bytes()))
		copy(mutated, sig.Bytes())
		bitPos := int(prng.nextU64() % SignatureSize)
		mutated[bitPos] ^= byte(0x01 << (prng.nextU64() % 8))
		badSig := &Signature{data: mutated}
		if Verify(pk, msg, badSig) {
			t.Fatalf("iteration %d: mutated signature must fail", i)
		}
	}
	t.Logf("Property: %d/%d mutated signatures correctly rejected", iterations, iterations)
}

func TestPropertyMutatePublicKeyFails(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping property test in short mode")
	}
	prng := newPrng(0xFEEDFACE12345678)
	iterations := 500

	for i := 0; i < iterations; i++ {
		seed := make([]byte, 32)
		prng.fillBytes(seed)
		pk, sk, err := KeypairFromSeed(seed)
		if err != nil {
			t.Fatal(err)
		}
		msg := prng.nextVec(32)
		sig, err := Sign(sk, msg)
		if err != nil {
			t.Fatal(err)
		}
		mutated := make([]byte, len(pk.Bytes()))
		copy(mutated, pk.Bytes())
		bitPos := int(prng.nextU64() % PublicKeySize)
		mutated[bitPos] ^= byte(0x01 << (prng.nextU64() % 8))
		badPk := &PublicKey{data: mutated}
		if Verify(badPk, msg, sig) {
			t.Fatalf("iteration %d: mutated public key must fail", i)
		}
	}
	t.Logf("Property: %d/%d mutated public keys correctly rejected", iterations, iterations)
}

func TestPropertyDifferentKeysDifferentSignatures(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping property test in short mode")
	}
	prng := newPrng(0xABCDEF0123456789)
	iterations := 100

	for i := 0; i < iterations; i++ {
		seed1 := make([]byte, 32)
		seed2 := make([]byte, 32)
		prng.fillBytes(seed1)
		prng.fillBytes(seed2)
		if bytes.Equal(seed1, seed2) {
			seed2[0] ^= 0x01
		}
		_, sk1, err := KeypairFromSeed(seed1)
		if err != nil {
			t.Fatal(err)
		}
		_, sk2, err := KeypairFromSeed(seed2)
		if err != nil {
			t.Fatal(err)
		}
		msg := prng.nextVec(32)
		sig1, err := Sign(sk1, msg)
		if err != nil {
			t.Fatal(err)
		}
		sig2, err := Sign(sk2, msg)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(sig1.Bytes(), sig2.Bytes()) {
			t.Fatalf("iteration %d: different keys should produce different signatures", i)
		}
	}
	t.Logf("Property: %d/%d different keys produced different signatures", iterations, iterations)
}

func TestPropertyKeySizesConstant(t *testing.T) {
	for i := 0; i < 100; i++ {
		pk, sk, err := GenerateKeypair()
		if err != nil {
			t.Fatal(err)
		}
		if len(pk.Bytes()) != PublicKeySize {
			t.Fatalf("public key size: got %d, want %d", len(pk.Bytes()), PublicKeySize)
		}
		if len(sk.Bytes()) != SecretKeySize {
			t.Fatalf("secret key size: got %d, want %d", len(sk.Bytes()), SecretKeySize)
		}
		sig, err := Sign(sk, []byte("test"))
		if err != nil {
			t.Fatal(err)
		}
		if len(sig.Bytes()) != SignatureSize {
			t.Fatalf("signature size: got %d, want %d", len(sig.Bytes()), SignatureSize)
		}
	}
	t.Logf("Property: 100/100 key sizes constant")
}
