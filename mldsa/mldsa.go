// Package mldsa implements ML-DSA-65 (FIPS 204) signature operations
// for the AAFP Go implementation.
//
// This wraps the github.com/KarpelesLab/mldsa library to provide
// the same API surface as the Rust aafp-crypto::dsa::MlDsa65.
//
// Key sizes (FIPS 204):
//   - Public key: 1952 bytes
//   - Secret key: 4032 bytes
//   - Signature: 3309 bytes
//
// The ML-DSA context string is empty (nil), matching the Rust
// implementation. Domain separation is applied at the application
// layer by prepending the domain separator to the message.
package mldsa

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"

	mldsalib "github.com/KarpelesLab/mldsa"
)

// Key sizes (FIPS 204 ML-DSA-65).
const (
	PublicKeySize = 1952
	SecretKeySize = 4032
	SignatureSize = 3309
	SeedSize      = 32
)

// Algorithm identifier (RFC-0003 §2.3).
const KeyAlgorithmID = 1

// AlgorithmName returns the human-readable algorithm name.
const AlgorithmName = "ML-DSA-65"

// Errors.
var (
	ErrInvalidKeyLength       = errors.New("mldsa65: invalid key length")
	ErrInvalidSignatureLength = errors.New("mldsa65: invalid signature length")
	ErrInvalidSeedLength      = errors.New("mldsa65: invalid seed length")
	ErrSigningFailed          = errors.New("mldsa65: signing failed")
	ErrKeyGenFailed           = errors.New("mldsa65: key generation failed")
)

// PublicKey holds a raw ML-DSA-65 public key (1952 bytes).
type PublicKey struct {
	data []byte
}

// SecretKey holds a raw ML-DSA-65 secret key (4032 bytes).
type SecretKey struct {
	data []byte
}

// Signature holds a raw ML-DSA-65 detached signature (3309 bytes).
type Signature struct {
	data []byte
}

// Bytes returns the raw key bytes.
func (pk *PublicKey) Bytes() []byte { return pk.data }

// Bytes returns the raw key bytes.
func (sk *SecretKey) Bytes() []byte { return sk.data }

// Bytes returns the raw signature bytes.
func (sig *Signature) Bytes() []byte { return sig.data }

// NewPublicKey decodes a raw ML-DSA-65 public key from bytes.
// Returns ErrInvalidKeyLength if the input is not 1952 bytes.
func NewPublicKey(b []byte) (*PublicKey, error) {
	if len(b) != PublicKeySize {
		return nil, fmt.Errorf("%w: expected %d, got %d", ErrInvalidKeyLength, PublicKeySize, len(b))
	}
	// Validate by attempting to construct the library type.
	_, err := mldsalib.NewPublicKey65(b)
	if err != nil {
		return nil, fmt.Errorf("mldsa65: invalid public key: %w", err)
	}
	return &PublicKey{data: append([]byte(nil), b...)}, nil
}

// NewSecretKey decodes a raw ML-DSA-65 secret key from bytes.
// Returns ErrInvalidKeyLength if the input is not 4032 bytes.
func NewSecretKey(b []byte) (*SecretKey, error) {
	if len(b) != SecretKeySize {
		return nil, fmt.Errorf("%w: expected %d, got %d", ErrInvalidKeyLength, SecretKeySize, len(b))
	}
	// Validate by attempting to construct the library type.
	_, err := mldsalib.NewPrivateKey65(b)
	if err != nil {
		return nil, fmt.Errorf("mldsa65: invalid secret key: %w", err)
	}
	return &SecretKey{data: append([]byte(nil), b...)}, nil
}

// NewSignature decodes a raw ML-DSA-65 signature from bytes.
// Returns ErrInvalidSignatureLength if the input is not 3309 bytes.
func NewSignature(b []byte) (*Signature, error) {
	if len(b) != SignatureSize {
		return nil, fmt.Errorf("%w: expected %d, got %d", ErrInvalidSignatureLength, SignatureSize, len(b))
	}
	return &Signature{data: append([]byte(nil), b...)}, nil
}

// GenerateKeypair generates a new ML-DSA-65 key pair using
// cryptographic random.
func GenerateKeypair() (*PublicKey, *SecretKey, error) {
	key, err := mldsalib.GenerateKey65(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrKeyGenFailed, err)
	}
	pk := key.PublicKey()
	skBytes := key.PrivateKeyBytes()
	return &PublicKey{data: pk.Bytes()}, &SecretKey{data: skBytes}, nil
}

// KeypairFromSeed generates a deterministic ML-DSA-65 key pair
// from a 32-byte seed (FIPS 204 Algorithm 1).
// The same seed produces the same keypair in all FIPS 204 implementations.
func KeypairFromSeed(seed []byte) (*PublicKey, *SecretKey, error) {
	if len(seed) != SeedSize {
		return nil, nil, fmt.Errorf("%w: expected %d, got %d", ErrInvalidSeedLength, SeedSize, len(seed))
	}
	key, err := mldsalib.NewKey65(seed)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrKeyGenFailed, err)
	}
	pk := key.PublicKey()
	skBytes := key.PrivateKeyBytes()
	return &PublicKey{data: pk.Bytes()}, &SecretKey{data: skBytes}, nil
}

// Sign signs a message using ML-DSA-65 with hedged (randomized) signing.
// The ML-DSA context string is empty (nil), matching the Rust implementation.
func Sign(sk *SecretKey, msg []byte) (*Signature, error) {
	privKey, err := mldsalib.NewPrivateKey65(sk.data)
	if err != nil {
		return nil, fmt.Errorf("mldsa65: invalid secret key: %w", err)
	}
	sig, err := privKey.SignWithContext(rand.Reader, msg, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSigningFailed, err)
	}
	return &Signature{data: sig}, nil
}

// SignDeterministic signs a message using ML-DSA-65 with deterministic
// signing (FIPS 204 deterministic variant, rnd = 0^32).
// The same key and message always produce the same signature.
func SignDeterministic(sk *SecretKey, msg []byte) (*Signature, error) {
	privKey, err := mldsalib.NewPrivateKey65(sk.data)
	if err != nil {
		return nil, fmt.Errorf("mldsa65: invalid secret key: %w", err)
	}
	// Deterministic signing: pass 32 zero bytes as the randomness source.
	// This is equivalent to FIPS 204's deterministic variant where rnd = 0^32.
	zeroReader := bytes.NewReader(make([]byte, 32))
	sig, err := privKey.SignWithContext(zeroReader, msg, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSigningFailed, err)
	}
	return &Signature{data: sig}, nil
}

// Verify verifies an ML-DSA-65 signature against a message and public key.
// The ML-DSA context string is empty (nil), matching the Rust implementation.
// Returns true if the signature is valid, false otherwise (including on
// malformed inputs — never panics).
func Verify(pk *PublicKey, msg []byte, sig *Signature) bool {
	if pk == nil || sig == nil || len(pk.data) != PublicKeySize || len(sig.data) != SignatureSize {
		return false
	}
	pubKey, err := mldsalib.NewPublicKey65(pk.data)
	if err != nil {
		return false
	}
	return pubKey.Verify(sig.data, msg, nil)
}
