// Package mldsa — negative testing (A-10 Phase 5).

package mldsa

import (
	"bytes"
	"testing"
)

func TestNegTruncatedSignature(t *testing.T) {
	pk, sk, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(sk, []byte("test message"))
	if err != nil {
		t.Fatal(err)
	}
	truncated := sig.Bytes()[:SignatureSize-1]
	badSig := &Signature{data: truncated}
	if Verify(pk, []byte("test message"), badSig) {
		t.Error("truncated signature must not verify")
	}
}

func TestNegOversizedSignature(t *testing.T) {
	pk, sk, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(sk, []byte("test message"))
	if err != nil {
		t.Fatal(err)
	}
	oversized := append(sig.Bytes(), 0x00)
	badSig := &Signature{data: oversized}
	if Verify(pk, []byte("test message"), badSig) {
		t.Error("oversized signature must not verify")
	}
}

func TestNegCorruptedSignatureSingleByte(t *testing.T) {
	pk, sk, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(sk, []byte("test message"))
	if err != nil {
		t.Fatal(err)
	}
	corrupted := make([]byte, len(sig.Bytes()))
	copy(corrupted, sig.Bytes())
	corrupted[0] ^= 0x01
	badSig := &Signature{data: corrupted}
	if Verify(pk, []byte("test message"), badSig) {
		t.Error("corrupted signature (1 bit) must not verify")
	}
}

func TestNegCorruptedSignatureAllBytes(t *testing.T) {
	pk, sk, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(sk, []byte("test message"))
	if err != nil {
		t.Fatal(err)
	}
	corrupted := make([]byte, len(sig.Bytes()))
	for i := range corrupted {
		corrupted[i] = sig.Bytes()[i] ^ 0xFF
	}
	badSig := &Signature{data: corrupted}
	if Verify(pk, []byte("test message"), badSig) {
		t.Error("fully corrupted signature must not verify")
	}
}

func TestNegCorruptedMessage(t *testing.T) {
	pk, sk, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(sk, []byte("original message"))
	if err != nil {
		t.Fatal(err)
	}
	if Verify(pk, []byte("corrupted message"), sig) {
		t.Error("corrupted message must not verify")
	}
}

func TestNegSingleBitMessageChange(t *testing.T) {
	pk, sk, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("test message for bit flip")
	sig, err := Sign(sk, msg)
	if err != nil {
		t.Fatal(err)
	}
	corrupted := make([]byte, len(msg))
	copy(corrupted, msg)
	corrupted[0] ^= 0x01
	if Verify(pk, corrupted, sig) {
		t.Error("single-bit message change must not verify")
	}
}

func TestNegCorruptedPublicKey(t *testing.T) {
	pk, sk, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(sk, []byte("test message"))
	if err != nil {
		t.Fatal(err)
	}
	corrupted := make([]byte, len(pk.Bytes()))
	copy(corrupted, pk.Bytes())
	corrupted[0] ^= 0x01
	badPk := &PublicKey{data: corrupted}
	if Verify(badPk, []byte("test message"), sig) {
		t.Error("corrupted public key must not verify")
	}
}

func TestNegWrongKey(t *testing.T) {
	pk1, sk1, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	pk2, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(sk1, []byte("test message"))
	if err != nil {
		t.Fatal(err)
	}
	if Verify(pk2, []byte("test message"), sig) {
		t.Error("wrong key must not verify")
	}
	if !Verify(pk1, []byte("test message"), sig) {
		t.Error("correct key must verify")
	}
}

func TestNegInvalidPublicKeyLength(t *testing.T) {
	if _, err := NewPublicKey([]byte{0x00}); err == nil {
		t.Error("10-byte public key must be rejected")
	}
	if _, err := NewPublicKey(make([]byte, 1951)); err == nil {
		t.Error("1951-byte public key must be rejected")
	}
	if _, err := NewPublicKey(make([]byte, 1953)); err == nil {
		t.Error("1953-byte public key must be rejected")
	}
}

func TestNegInvalidSecretKeyLength(t *testing.T) {
	if _, err := NewSecretKey([]byte{0x00}); err == nil {
		t.Error("10-byte secret key must be rejected")
	}
	if _, err := NewSecretKey(make([]byte, 4031)); err == nil {
		t.Error("4031-byte secret key must be rejected")
	}
	if _, err := NewSecretKey(make([]byte, 4033)); err == nil {
		t.Error("4033-byte secret key must be rejected")
	}
}

func TestNegInvalidSignatureLength(t *testing.T) {
	if _, err := NewSignature([]byte{0x00}); err == nil {
		t.Error("10-byte signature must be rejected")
	}
	if _, err := NewSignature(make([]byte, 3308)); err == nil {
		t.Error("3308-byte signature must be rejected")
	}
	if _, err := NewSignature(make([]byte, 3310)); err == nil {
		t.Error("3310-byte signature must be rejected")
	}
}

func TestNegEmptyMessageValidSig(t *testing.T) {
	pk, sk, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(sk, []byte{})
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(pk, []byte{}, sig) {
		t.Error("empty message with valid signature should verify")
	}
	if Verify(pk, []byte("x"), sig) {
		t.Error("empty message sig should not verify against non-empty message")
	}
}

func TestNegAllZeroSignature(t *testing.T) {
	pk, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	sig := &Signature{data: make([]byte, SignatureSize)}
	if Verify(pk, []byte("test message"), sig) {
		t.Error("all-zero signature must not verify")
	}
}

func TestNegAllFFSignature(t *testing.T) {
	pk, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	ffSig := make([]byte, SignatureSize)
	for i := range ffSig {
		ffSig[i] = 0xFF
	}
	sig := &Signature{data: ffSig}
	if Verify(pk, []byte("test message"), sig) {
		t.Error("all-FF signature must not verify")
	}
}

func TestNegNoPanicOnMalformedInputs(t *testing.T) {
	pk, sk, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(sk, []byte("test"))
	if err != nil {
		t.Fatal(err)
	}

	// Various malformed signatures — must not panic.
	_ = Verify(pk, []byte("test"), &Signature{data: []byte{}})
	_ = Verify(pk, []byte("test"), &Signature{data: []byte{0x00}})
	_ = Verify(pk, []byte("test"), &Signature{data: make([]byte, SignatureSize)})
	_ = Verify(pk, []byte("test"), &Signature{data: bytes.Repeat([]byte{0xFF}, SignatureSize)})

	// Various malformed public keys — must not panic.
	_ = Verify(&PublicKey{data: []byte{}}, []byte("test"), sig)
	_ = Verify(&PublicKey{data: []byte{0x00}}, []byte("test"), sig)
	_ = Verify(&PublicKey{data: make([]byte, PublicKeySize)}, []byte("test"), sig)
}
