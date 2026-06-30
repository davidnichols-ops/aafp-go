package mldsa

import (
	"bytes"
	"testing"
)

func TestGenerateKeypair(t *testing.T) {
	pk, sk, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if len(pk.Bytes()) != PublicKeySize {
		t.Errorf("public key size: got %d, want %d", len(pk.Bytes()), PublicKeySize)
	}
	if len(sk.Bytes()) != SecretKeySize {
		t.Errorf("secret key size: got %d, want %d", len(sk.Bytes()), SecretKeySize)
	}
}

func TestKeypairFromSeedDeterministic(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, 32)
	pk1, sk1, err := KeypairFromSeed(seed)
	if err != nil {
		t.Fatalf("KeypairFromSeed: %v", err)
	}
	pk2, sk2, err := KeypairFromSeed(seed)
	if err != nil {
		t.Fatalf("KeypairFromSeed (2nd): %v", err)
	}
	if !bytes.Equal(pk1.Bytes(), pk2.Bytes()) {
		t.Error("same seed must produce same public key")
	}
	if !bytes.Equal(sk1.Bytes(), sk2.Bytes()) {
		t.Error("same seed must produce same secret key")
	}
}

func TestKeypairFromSeedDifferentSeeds(t *testing.T) {
	seed1 := bytes.Repeat([]byte{0x01}, 32)
	seed2 := bytes.Repeat([]byte{0x02}, 32)
	pk1, _, err := KeypairFromSeed(seed1)
	if err != nil {
		t.Fatal(err)
	}
	pk2, _, err := KeypairFromSeed(seed2)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(pk1.Bytes(), pk2.Bytes()) {
		t.Error("different seeds must produce different keys")
	}
}

func TestSignVerifyRoundtrip(t *testing.T) {
	pk, sk, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("post-quantum aafp")
	sig, err := Sign(sk, msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig.Bytes()) != SignatureSize {
		t.Errorf("signature size: got %d, want %d", len(sig.Bytes()), SignatureSize)
	}
	if !Verify(pk, msg, sig) {
		t.Error("signature verification failed")
	}
}

func TestVerifyRejectsTamperedMessage(t *testing.T) {
	pk, sk, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(sk, []byte("original"))
	if err != nil {
		t.Fatal(err)
	}
	if Verify(pk, []byte("tampered"), sig) {
		t.Error("tampered message should not verify")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	pk1, sk1, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	pk2, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(sk1, []byte("msg"))
	if err != nil {
		t.Fatal(err)
	}
	if Verify(pk2, []byte("msg"), sig) {
		t.Error("wrong key should not verify")
	}
	if !Verify(pk1, []byte("msg"), sig) {
		t.Error("correct key should verify")
	}
}

func TestSerializationRoundtrip(t *testing.T) {
	pk, sk, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	pk2, err := NewPublicKey(pk.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	sk2, err := NewSecretKey(sk.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(sk2, []byte("roundtrip"))
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(pk2, []byte("roundtrip"), sig) {
		t.Error("serialization roundtrip failed")
	}
}

func TestRejectsBadLengths(t *testing.T) {
	if _, err := NewPublicKey([]byte{0x00}); err == nil {
		t.Error("bad public key length should fail")
	}
	if _, err := NewSecretKey([]byte{0x00}); err == nil {
		t.Error("bad secret key length should fail")
	}
	if _, err := NewSignature([]byte{0x00}); err == nil {
		t.Error("bad signature length should fail")
	}
}

func TestSignDeterministicReproducible(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, 32)
	pk, sk, err := KeypairFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("test message for deterministic signing")
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
		t.Error("deterministic signature should verify")
	}
}

func TestSignDeterministicVerifiesWithNormalVerify(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, 32)
	pk, sk, err := KeypairFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("cross-verification test")
	sig, err := SignDeterministic(sk, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(pk, msg, sig) {
		t.Error("deterministic signature should verify with normal verify")
	}
}

func TestKeypairFromSeedBadLength(t *testing.T) {
	if _, _, err := KeypairFromSeed([]byte{0x00}); err == nil {
		t.Error("bad seed length should fail")
	}
}
