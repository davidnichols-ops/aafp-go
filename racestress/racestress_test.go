// Package racestress contains concurrent stress tests designed to
// exercise the Go race detector under representative workloads:
// concurrent frame encoding/decoding, parallel CBOR operations,
// and simulated multi-stream handling.
package racestress

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"

	"aafp-go/cbor"
	"aafp-go/frame"
	"aafp-go/handshake"
	"aafp-go/identity"
)

// TestConcurrentFrameEncodeDecode races frame encoding and decoding
// across multiple goroutines to detect any shared-state issues.
func TestConcurrentFrameEncodeDecode(t *testing.T) {
	const goroutines = 16
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				streamID := uint64(id*1000 + i)
				payload := []byte(fmt.Sprintf("goroutine-%d-iter-%d-payload", id, i))

				f := frame.Frame{
					Version:   1,
					FrameType: frame.TypeData,
					Flags:     0,
					StreamID:  streamID,
					Payload:   payload,
				}

				encoded, err := frame.Encode(&f)
				if err != nil {
					t.Errorf("goroutine %d: encode error: %v", id, err)
					return
				}

				decoded, n, err := frame.Decode(encoded)
				if err != nil {
					t.Errorf("goroutine %d: decode error: %v", id, err)
					return
				}
				if n != len(encoded) {
					t.Errorf("goroutine %d: consumed %d, expected %d", id, n, len(encoded))
				}
				if decoded.StreamID != streamID {
					t.Errorf("goroutine %d: streamID %d, expected %d", id, decoded.StreamID, streamID)
				}
				if !bytes.Equal(decoded.Payload, payload) {
					t.Errorf("goroutine %d: payload mismatch", id)
				}
			}
		}(g)
	}
	wg.Wait()
}

// TestConcurrentCBOREncodeDecode races CBOR encoding and decoding
// across multiple goroutines with diverse value types.
func TestConcurrentCBOREncodeDecode(t *testing.T) {
	const goroutines = 16
	const iterations = 100

	values := []cbor.Value{
		cbor.UUint(42),
		cbor.UUint(1000000),
		cbor.NInt(-1),
		cbor.BStr([]byte{0x01, 0x02, 0x03, 0x04}),
		cbor.TStr("hello world"),
		cbor.Arr([]cbor.Value{cbor.UUint(1), cbor.UUint(2), cbor.UUint(3)}),
		cbor.IMap([]cbor.IntMapEntry{
			{Key: 1, Value: cbor.TStr("a")},
			{Key: 2, Value: cbor.UUint(99)},
		}),
		cbor.SMap([]cbor.StrMapEntry{
			{Key: "x", Value: cbor.UUint(1)},
			{Key: "y", Value: cbor.TStr("z")},
		}),
	}

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				v := values[(id+i)%len(values)]
				encoded, err := cbor.Encode(&v)
				if err != nil {
					t.Errorf("goroutine %d: encode error: %v", id, err)
					return
				}
				decoded, n, err := cbor.Decode(encoded)
				if err != nil {
					t.Errorf("goroutine %d: decode error: %v", id, err)
					return
				}
				if n != len(encoded) {
					t.Errorf("goroutine %d: consumed %d, expected %d", id, n, len(encoded))
				}
				_ = decoded
			}
		}(g)
	}
	wg.Wait()
}

// TestConcurrentTranscriptHash races transcript hash computation
// across multiple goroutines with different TLS bindings and messages.
func TestConcurrentTranscriptHash(t *testing.T) {
	const goroutines = 8
	const messages = 10

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			tlsBinding := make([]byte, 32)
			tlsBinding[0] = byte(id)

			th := handshake.NewTranscriptHash(tlsBinding)
			for m := 0; m < messages; m++ {
				msg := []byte(fmt.Sprintf("message-%d-%d", id, m))
				th.Update(msg)
				hash := th.Current()
				if len(hash) != 32 {
					t.Errorf("goroutine %d: hash length %d, expected 32", id, len(hash))
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

// TestConcurrentAgentIdDerivation races AgentId derivation from
// different public keys across goroutines.
func TestConcurrentAgentIdDerivation(t *testing.T) {
	const goroutines = 16
	const iterations = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				pk := make([]byte, 1952)
				pk[0] = byte(id)
				pk[1] = byte(i)
				pk[2] = byte(i >> 8)

				agentID := identity.AgentIdFromPubkey(pk)
				if len(agentID) != 32 {
					t.Errorf("goroutine %d: AgentId length %d, expected 32", id, len(agentID))
					return
				}

				// Verify determinism: same key should produce same ID
				agentID2 := identity.AgentIdFromPubkey(pk)
				if !bytes.Equal(agentID, agentID2) {
					t.Errorf("goroutine %d: AgentId not deterministic", id)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

// TestConcurrentMixedOperations races a mix of all operations
// simultaneously to catch interactions between different components.
func TestConcurrentMixedOperations(t *testing.T) {
	const goroutines = 32
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			switch id % 4 {
			case 0:
				// Frame encode/decode
				f := frame.Frame{
					Version:   1,
					FrameType: frame.TypeData,
					StreamID:  uint64(id),
					Payload:   []byte{byte(id), byte(id >> 8)},
				}
				enc, _ := frame.Encode(&f)
				_, _, err := frame.Decode(enc)
				if err != nil {
					t.Errorf("frame decode error: %v", err)
				}

			case 1:
				// CBOR encode/decode
				v := cbor.IMap([]cbor.IntMapEntry{
					{Key: 1, Value: cbor.UUint(uint64(id))},
				})
				enc, _ := cbor.Encode(&v)
				_, _, err := cbor.Decode(enc)
				if err != nil {
					t.Errorf("cbor decode error: %v", err)
				}

			case 2:
				// Transcript hash
				binding := make([]byte, 32)
				binding[0] = byte(id)
				th := handshake.NewTranscriptHash(binding)
				th.Update([]byte("test"))
				_ = th.Current()

			case 3:
				// AgentId derivation
				pk := make([]byte, 1952)
				pk[0] = byte(id)
				_ = identity.AgentIdFromPubkey(pk)
			}
		}(g)
	}
	wg.Wait()
}

// TestConcurrentAgentRecordBuild races AgentRecord construction
// and CBOR serialization across goroutines.
func TestConcurrentAgentRecordBuild(t *testing.T) {
	const goroutines = 8
	const iterations = 25

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				pk := make([]byte, 1952)
				for j := range pk {
					pk[j] = byte((id*7 + i*13 + j) % 256)
				}

				record := &identity.AgentRecord{
					RecordType:   identity.RecordTypeV1,
					AgentId:      identity.AgentIdFromPubkey(pk),
					PublicKey:    pk,
					Capabilities: []identity.CapabilityDescriptor{{Name: "inference"}},
					Endpoints:    []string{fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", 4000+id)},
					CreatedAt:    1700000000,
					ExpiresAt:    1700000000 + 86400,
					Signature:    make([]byte, 3309),
					KeyAlgorithm: identity.KeyAlgMLDSA65,
				}

				v := record.ToCBOR()
				encoded, err := cbor.Encode(&v)
				if err != nil {
					t.Errorf("goroutine %d: encode error: %v", id, err)
					return
				}

				decoded, _, err := cbor.Decode(encoded)
				if err != nil {
					t.Errorf("goroutine %d: decode error: %v", id, err)
					return
				}

				_, err = identity.AgentRecordFromCBOR(decoded)
				if err != nil {
					t.Errorf("goroutine %d: AgentRecordFromCBOR error: %v", id, err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

// TestConcurrentHexEncoding races hex encoding/decoding to verify
// that the standard library hex functions are goroutine-safe
// when used in our test infrastructure.
func TestConcurrentHexEncoding(t *testing.T) {
	const goroutines = 16
	const iterations = 200

	data := make([]byte, 32)
	for i := range data {
		data[i] = byte(i)
	}

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				encoded := hex.EncodeToString(data)
				decoded, err := hex.DecodeString(encoded)
				if err != nil {
					t.Errorf("goroutine %d: hex decode error: %v", id, err)
					return
				}
				if !bytes.Equal(decoded, data) {
					t.Errorf("goroutine %d: hex roundtrip mismatch", id)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

// TestConcurrentSHA256 races SHA-256 hashing to verify that
// the standard library hash functions are goroutine-safe.
func TestConcurrentSHA256(t *testing.T) {
	const goroutines = 16
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				input := []byte(fmt.Sprintf("hash-input-%d-%d", id, i))
				h := sha256.Sum256(input)
				if len(h) != 32 {
					t.Errorf("goroutine %d: hash length %d, expected 32", id, len(h))
					return
				}
			}
		}(g)
	}
	wg.Wait()
}
