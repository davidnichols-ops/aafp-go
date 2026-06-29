// Package identity_test contains conformance tests for RFC Revision 4
// clarifications SA-0001 and SA-0002.
package identity_test

import (
	"testing"

	"aafp-go/cbor"
	"aafp-go/identity"
)

// R4-001 (SA-0001): CapabilityDescriptor metadata (key 2) MUST always
// be present on the wire, even when empty.
func TestR4_001_MetadataAlwaysPresent(t *testing.T) {
	cap := &identity.CapabilityDescriptor{Name: "inference"}
	v := cap.ToCBOR()

	// Key 2 must be present
	meta := v.IntMapGet(2)
	if meta == nil {
		t.Fatal("metadata (key 2) MUST always be present per RFC-0003 §4.4 (Revision 4)")
	}
}

// R4-002 (SA-0001): Empty metadata MUST be encoded as an empty CBOR
// map (0xa0), not omitted.
func TestR4_002_EmptyMetadataEncodedAsEmptyMap(t *testing.T) {
	cap := &identity.CapabilityDescriptor{Name: "inference"}
	v := cap.ToCBOR()

	encoded, err := cbor.Encode(&v)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	// The encoded bytes must contain 0xa0 for the empty map
	found := false
	for _, b := range encoded {
		if b == 0xa0 {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("encoded bytes must contain 0xa0 for empty metadata map")
	}
}

// R4-003 (SA-0001): Two CapabilityDescriptors with empty metadata must
// produce identical CBOR byte sequences (deterministic encoding).
func TestR4_003_EmptyMetadataDeterministic(t *testing.T) {
	cap1 := &identity.CapabilityDescriptor{Name: "inference"}
	cap2 := &identity.CapabilityDescriptor{Name: "inference"}

	v1 := cap1.ToCBOR()
	v2 := cap2.ToCBOR()

	enc1, err := cbor.Encode(&v1)
	if err != nil {
		t.Fatalf("encode cap1: %v", err)
	}
	enc2, err := cbor.Encode(&v2)
	if err != nil {
		t.Fatalf("encode cap2: %v", err)
	}

	if len(enc1) != len(enc2) {
		t.Fatalf("lengths differ: %d vs %d", len(enc1), len(enc2))
	}
	for i := range enc1 {
		if enc1[i] != enc2[i] {
			t.Fatalf("byte %d differs: 0x%02x vs 0x%02x", i, enc1[i], enc2[i])
		}
	}
}

// R4-004 (SA-0001): AgentRecord with empty-metadata CapabilityDescriptor
// must round-trip and preserve the metadata field.
func TestR4_004_RecordWithEmptyMetadataRoundtrip(t *testing.T) {
	pk := make([]byte, 1952)
	for i := range pk {
		pk[i] = byte(i % 256)
	}

	record := &identity.AgentRecord{
		RecordType:   identity.RecordTypeV1,
		AgentId:      identity.AgentIdFromPubkey(pk),
		PublicKey:    pk,
		Capabilities: []identity.CapabilityDescriptor{{Name: "inference"}},
		Endpoints:    []string{"/ip4/127.0.0.1/tcp/4001"},
		CreatedAt:    1700000000,
		ExpiresAt:    1700000000 + 86400,
		Signature:    make([]byte, 3309),
		KeyAlgorithm: identity.KeyAlgMLDSA65,
	}

	v := record.ToCBOR()
	encoded, err := cbor.Encode(&v)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	decoded, _, err := cbor.Decode(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	record2, err := identity.AgentRecordFromCBOR(decoded)
	if err != nil {
		t.Fatalf("AgentRecordFromCBOR: %v", err)
	}

	if len(record2.Capabilities) != 1 {
		t.Fatalf("expected 1 capability, got %d", len(record2.Capabilities))
	}
	if record2.Capabilities[0].Name != "inference" {
		t.Fatalf("expected name 'inference', got '%s'", record2.Capabilities[0].Name)
	}
}

// R4-005 (SA-0002): An empty CBOR map in the metadata field must be
// decoded as a string-keyed map, not rejected as a type mismatch.
func TestR4_005_EmptyMapSchemaDrivenKeytype(t *testing.T) {
	// Construct a CapabilityDescriptor CBOR with an empty StrMap at key 2
	cap := cbor.IMap([]cbor.IntMapEntry{
		{Key: 1, Value: cbor.TStr("inference")},
		{Key: 2, Value: cbor.SMap(nil)},
	})

	encoded, err := cbor.Encode(&cap)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	decoded, _, err := cbor.Decode(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	cap2, err := identity.CapabilityFromCBOR(decoded)
	if err != nil {
		t.Fatalf("CapabilityFromCBOR must accept empty metadata map per SA-0002: %v", err)
	}

	if cap2.Name != "inference" {
		t.Fatalf("expected name 'inference', got '%s'", cap2.Name)
	}
}

// R4-006 (SA-0002): An empty CBOR map encoded as IntMap (major type 5)
// in a string-keyed schema field must also be accepted, since the
// schema defines the key type, not the CBOR major type.
func TestR4_006_EmptyIntMapInStringFieldAccepted(t *testing.T) {
	// Construct CBOR with key 2 as an empty IntMap instead of StrMap.
	// On the wire, both encode as 0xa0. The decoder must accept either.
	cap := cbor.IMap([]cbor.IntMapEntry{
		{Key: 1, Value: cbor.TStr("inference")},
		{Key: 2, Value: cbor.IMap(nil)},
	})

	encoded, err := cbor.Encode(&cap)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	decoded, _, err := cbor.Decode(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	cap2, err := identity.CapabilityFromCBOR(decoded)
	if err != nil {
		t.Fatalf("CapabilityFromCBOR must accept empty map regardless of CBOR major type per SA-0002: %v", err)
	}

	if cap2.Name != "inference" {
		t.Fatalf("expected name 'inference', got '%s'", cap2.Name)
	}
}

// R4-007 (SA-0002): Empty IntMap and empty StrMap must produce
// identical bytes on the wire (both 0xa0).
func TestR4_007_EmptyMapsSameEncoding(t *testing.T) {
	intEmpty := cbor.IMap(nil)
	strEmpty := cbor.SMap(nil)

	intBytes, err := cbor.Encode(&intEmpty)
	if err != nil {
		t.Fatalf("encode int empty: %v", err)
	}
	strBytes, err := cbor.Encode(&strEmpty)
	if err != nil {
		t.Fatalf("encode str empty: %v", err)
	}

	if len(intBytes) != 1 || intBytes[0] != 0xa0 {
		t.Fatalf("empty IntMap must encode as [0xa0], got %v", intBytes)
	}
	if len(strBytes) != 1 || strBytes[0] != 0xa0 {
		t.Fatalf("empty StrMap must encode as [0xa0], got %v", strBytes)
	}
}
