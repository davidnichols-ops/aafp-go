// Package identity implements AAFP identity structures per RFC-0003:
//   - AgentId (SHA-256 of public key)
//   - AgentRecord (self-signed CBOR document)
//   - CapabilityDescriptor
//
// This implementation is written from the RFC specification alone.
package identity

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"aafp-go/cbor"
)

const (
	RecordTypeV1   = "aafp-record-v1"
	KeyAlgMLDSA65  = 1
	// MaxRecordExpiry is the 30-day deployment mitigation threshold
	// (RFC-0003 §8.4, clarified in Revision 5). This is a warning
	// threshold, NOT a verification-rejection requirement. verify()
	// does NOT reject records whose lifetime exceeds 30 days.
	MaxRecordExpiry = 30 * 24 * 60 * 60 // 2,592,000 seconds
)

// AgentIdFromPubkey computes AgentId = SHA-256(public_key) per RFC-0003 §2.1.
func AgentIdFromPubkey(pubkey []byte) []byte {
	h := sha256.Sum256(pubkey)
	return h[:]
}

// VerifyAgentId checks that agentId == SHA-256(pubkey).
func VerifyAgentId(agentId, pubkey []byte) bool {
	expected := AgentIdFromPubkey(pubkey)
	if len(agentId) != 32 || len(expected) != 32 {
		return false
	}
	return constantTimeEq(agentId, expected)
}

func constantTimeEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var r byte
	for i := range a {
		r |= a[i] ^ b[i]
	}
	return r == 0
}

// CapabilityDescriptor represents a single capability per RFC-0003 §4.
type CapabilityDescriptor struct {
	Name     string
	Metadata map[string]cbor.Value // optional, may be nil
}

// ToCBOR encodes a CapabilityDescriptor as a CBOR map with integer keys.
// Key 2 (metadata) is always present, even when empty (per RFC-0003 §4.4,
// Revision 4 clarification SA-0001).
func (c *CapabilityDescriptor) ToCBOR() cbor.Value {
	entries := []cbor.IntMapEntry{
		{Key: 1, Value: cbor.TStr(c.Name)},
	}
	strEntries := make([]cbor.StrMapEntry, 0, len(c.Metadata))
	for k, v := range c.Metadata {
		strEntries = append(strEntries, cbor.StrMapEntry{Key: k, Value: v})
	}
	entries = append(entries, cbor.IntMapEntry{
		Key:   2,
		Value: cbor.SMap(strEntries),
	})
	return cbor.IMap(entries)
}

// CapabilityFromCBOR decodes a CapabilityDescriptor from a CBOR map.
func CapabilityFromCBOR(v *cbor.Value) (*CapabilityDescriptor, error) {
	if v.Kind() != cbor.KindIntMap {
		return nil, errors.New("capability: expected int map")
	}
	nameVal := v.IntMapGet(1)
	if nameVal == nil || nameVal.Kind() != cbor.KindTextString {
		return nil, errors.New("capability: missing or invalid name (key 1)")
	}
	cap := &CapabilityDescriptor{Name: nameVal.Str()}
	if metaVal := v.IntMapGet(2); metaVal != nil {
		// Metadata is a string-keyed map. However, an empty CBOR map (a0)
		// is ambiguous — the decoder can't distinguish int-keyed from
		// string-keyed when there are no entries. Treat both empty
		// IntMap and StrMap as empty metadata.
		if metaVal.Kind() == cbor.KindStrMap {
			cap.Metadata = make(map[string]cbor.Value)
			for _, e := range metaVal.StrMap() {
				cap.Metadata[e.Key] = e.Value
			}
		} else if metaVal.Kind() == cbor.KindIntMap && len(metaVal.IntMap()) == 0 {
			// Empty map — treat as empty metadata (ambiguous decode)
			cap.Metadata = make(map[string]cbor.Value)
		} else if metaVal.Kind() == cbor.KindNull {
			// Null metadata — treat as empty
			cap.Metadata = make(map[string]cbor.Value)
		} else {
			return nil, errors.New("capability: metadata must be string map")
		}
	}
	return cap, nil
}

// AgentRecord represents an AAFP AgentRecord per RFC-0003 §3.
type AgentRecord struct {
	RecordType   string
	AgentId      []byte
	PublicKey    []byte
	Capabilities []CapabilityDescriptor
	Endpoints    []string
	CreatedAt    uint64
	ExpiresAt    uint64
	Signature    []byte
	KeyAlgorithm uint64
}

// ToCBORWithoutSig encodes the AgentRecord as CBOR excluding the signature
// field (key 8). This is the signature input per RFC-0003 §3.4.
func (r *AgentRecord) ToCBORWithoutSig() cbor.Value {
	entries := []cbor.IntMapEntry{
		{Key: 1, Value: cbor.TStr(r.RecordType)},
		{Key: 2, Value: cbor.BStr(r.AgentId)},
		{Key: 3, Value: cbor.BStr(r.PublicKey)},
	}
	// Capabilities array
	caps := make([]cbor.Value, len(r.Capabilities))
	for i, c := range r.Capabilities {
		caps[i] = c.ToCBOR()
	}
	entries = append(entries, cbor.IntMapEntry{Key: 4, Value: cbor.Arr(caps)})
	// Endpoints array
	eps := make([]cbor.Value, len(r.Endpoints))
	for i, e := range r.Endpoints {
		eps[i] = cbor.TStr(e)
	}
	entries = append(entries, cbor.IntMapEntry{Key: 5, Value: cbor.Arr(eps)})
	entries = append(entries, cbor.IntMapEntry{Key: 6, Value: cbor.UUint(r.CreatedAt)})
	entries = append(entries, cbor.IntMapEntry{Key: 7, Value: cbor.UUint(r.ExpiresAt)})
	// Key 8 (signature) is excluded — this is the signature input
	entries = append(entries, cbor.IntMapEntry{Key: 9, Value: cbor.UUint(r.KeyAlgorithm)})
	return cbor.IMap(entries)
}

// ToCBOR encodes the full AgentRecord including signature.
func (r *AgentRecord) ToCBOR() cbor.Value {
	v := r.ToCBORWithoutSig()
	// Add signature as key 8
	entries := v.IntMap()
	entries = append(entries, cbor.IntMapEntry{Key: 8, Value: cbor.BStr(r.Signature)})
	return cbor.IMap(entries)
}

// AgentRecordFromCBOR decodes an AgentRecord from a CBOR map.
func AgentRecordFromCBOR(v *cbor.Value) (*AgentRecord, error) {
	if v.Kind() != cbor.KindIntMap {
		return nil, errors.New("record: expected int map")
	}
	r := &AgentRecord{}

	if val := v.IntMapGet(1); val != nil && val.Kind() == cbor.KindTextString {
		r.RecordType = val.Str()
	} else {
		return nil, errors.New("record: missing record_type (key 1)")
	}
	if val := v.IntMapGet(2); val != nil && val.Kind() == cbor.KindByteString {
		r.AgentId = val.Bytes()
	} else {
		return nil, errors.New("record: missing agent_id (key 2)")
	}
	if val := v.IntMapGet(3); val != nil && val.Kind() == cbor.KindByteString {
		r.PublicKey = val.Bytes()
	} else {
		return nil, errors.New("record: missing public_key (key 3)")
	}
	if val := v.IntMapGet(4); val != nil && val.Kind() == cbor.KindArray {
		for _, capVal := range val.Arr() {
			cap, err := CapabilityFromCBOR(&capVal)
			if err != nil {
				return nil, fmt.Errorf("record: bad capability: %w", err)
			}
			r.Capabilities = append(r.Capabilities, *cap)
		}
	}
	if val := v.IntMapGet(5); val != nil && val.Kind() == cbor.KindArray {
		for _, epVal := range val.Arr() {
			if epVal.Kind() == cbor.KindTextString {
				r.Endpoints = append(r.Endpoints, epVal.Str())
			}
		}
	}
	if val := v.IntMapGet(6); val != nil && val.Kind() == cbor.KindUnsigned {
		r.CreatedAt = val.Uint()
	}
	if val := v.IntMapGet(7); val != nil && val.Kind() == cbor.KindUnsigned {
		r.ExpiresAt = val.Uint()
	}
	if val := v.IntMapGet(8); val != nil && val.Kind() == cbor.KindByteString {
		r.Signature = val.Bytes()
	}
	if val := v.IntMapGet(9); val != nil && val.Kind() == cbor.KindUnsigned {
		r.KeyAlgorithm = val.Uint()
	}
	return r, nil
}

// SignatureInput returns the bytes to be signed/verified per RFC-0003 §3.4:
//   sig_input = "aafp-v1-record" || canonical_CBOR(fields 1-7, 9)
func (r *AgentRecord) SignatureInput() ([]byte, error) {
	cborVal := r.ToCBORWithoutSig()
	cborBytes, err := cbor.Encode(&cborVal)
	if err != nil {
		return nil, err
	}
	domain := []byte("aafp-v1-record")
	return append(domain, cborBytes...), nil
}

// Verify checks the AgentRecord per RFC-0003 §3.6.
// The verifyFn parameter performs the actual ML-DSA-65 signature verification.
// This separation allows the identity module to be tested without a crypto
// dependency.
func (r *AgentRecord) Verify(currentTime uint64, verifyFn func(pubkey, msg, sig []byte) bool) error {
	// Step 2: Verify agent_id == SHA-256(public_key)
	if !VerifyAgentId(r.AgentId, r.PublicKey) {
		return errors.New("record: invalid agent_id (does not match SHA-256(public_key))")
	}
	// Step 7: Check record_type
	if r.RecordType != RecordTypeV1 {
		return fmt.Errorf("record: invalid record_type %q", r.RecordType)
	}
	// Step 8: Check key_algorithm
	if r.KeyAlgorithm != KeyAlgMLDSA65 {
		return fmt.Errorf("record: unsupported key_algorithm %d", r.KeyAlgorithm)
	}
	// Step 3-5: Verify signature
	sigInput, err := r.SignatureInput()
	if err != nil {
		return err
	}
	if !verifyFn(r.PublicKey, sigInput, r.Signature) {
		return errors.New("record: signature verification failed")
	}
	// Step 6: Check expiry
	if r.ExpiresAt <= currentTime {
		return errors.New("record: expired")
	}
	return nil
}

// ExceedsMaxExpiryWarning checks whether the record's expiry exceeds the
// 30-day deployment mitigation threshold (RFC-0003 §8.4, clarified in
// Revision 5).
//
// Per RFC-0003 §8.4 (Revision 5), the 30-day limit is a deployment
// mitigation, NOT a verification requirement. Verify does NOT reject
// records whose lifetime exceeds 30 days. Callers SHOULD use this method
// to warn users when ExpiresAt - now > 30 days.
//
// The predicate is computed from the current time (now), not from
// CreatedAt, matching the §8.4 normative text: "expires_at exceeds
// 30 days from the current time."
func (r *AgentRecord) ExceedsMaxExpiryWarning(now uint64) bool {
	if r.ExpiresAt <= now {
		return false // already expired or at expiry: no future-lifetime warning
	}
	return (r.ExpiresAt - now) > MaxRecordExpiry
}
