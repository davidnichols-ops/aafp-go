// Package mldsa — performance benchmarks (A-10 Phase 7).

package mldsa

import (
	"crypto/rand"
	"testing"
)

func BenchmarkMlDsa65Keypair(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, err := GenerateKeypair()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMlDsa65KeypairFromSeed(b *testing.B) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 0x42
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := KeypairFromSeed(seed)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMlDsa65Sign(b *testing.B) {
	_, sk, err := GenerateKeypair()
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("benchmark message for ML-DSA-65 signing")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Sign(sk, msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMlDsa65SignDeterministic(b *testing.B) {
	_, sk, err := GenerateKeypair()
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("benchmark message for ML-DSA-65 deterministic signing")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := SignDeterministic(sk, msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMlDsa65Verify(b *testing.B) {
	pk, sk, err := GenerateKeypair()
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("benchmark message for ML-DSA-65 verification")
	sig, err := Sign(sk, msg)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !Verify(pk, msg, sig) {
			b.Fatal("verification failed")
		}
	}
}

func BenchmarkMlDsa65VerifyInvalid(b *testing.B) {
	pk, sk, err := GenerateKeypair()
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("benchmark message for ML-DSA-65 verification")
	sig, err := Sign(sk, msg)
	if err != nil {
		b.Fatal(err)
	}
	wrongMsg := []byte("wrong message")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if Verify(pk, wrongMsg, sig) {
			b.Fatal("invalid verification should fail")
		}
	}
}

func BenchmarkMlDsa65DecodePublicKey(b *testing.B) {
	pk, _, err := GenerateKeypair()
	if err != nil {
		b.Fatal(err)
	}
	data := pk.Bytes()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := NewPublicKey(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMlDsa65DecodeSecretKey(b *testing.B) {
	_, sk, err := GenerateKeypair()
	if err != nil {
		b.Fatal(err)
	}
	data := sk.Bytes()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := NewSecretKey(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMlDsa65DecodeSignature(b *testing.B) {
	_, sk, err := GenerateKeypair()
	if err != nil {
		b.Fatal(err)
	}
	sig, err := Sign(sk, []byte("msg"))
	if err != nil {
		b.Fatal(err)
	}
	data := sig.Bytes()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := NewSignature(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Ensure rand is used to avoid unused import warning.
var _ = rand.Reader
