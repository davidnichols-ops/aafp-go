// Package identity_test contains conformance tests for RFC Revision 5
// clarification SA-0003: the AgentRecord 30-day expiry limit is a
// deployment warning, not a verification-rejection requirement.
package identity_test

import (
	"testing"

	"aafp-go/identity"
)

// alwaysTrueVerifyFn is a verifyFn callback that always returns true.
// It is used for tests that exercise expiry behavior, not signature
// verification (the signature bytes are placeholder zeros).
func alwaysTrueVerifyFn(pubkey, msg, sig []byte) bool { return true }

// makeRecord builds an AgentRecord with the given created/expires times
// and placeholder signature/key bytes sufficient for structural tests.
func makeRecord(t *testing.T, createdAt, expiresAt uint64) *identity.AgentRecord {
	t.Helper()
	pk := make([]byte, 1952)
	for i := range pk {
		pk[i] = byte(i % 256)
	}
	return &identity.AgentRecord{
		RecordType:   identity.RecordTypeV1,
		AgentId:      identity.AgentIdFromPubkey(pk),
		PublicKey:    pk,
		Capabilities: []identity.CapabilityDescriptor{{Name: "inference"}},
		Endpoints:    []string{"/ip4/127.0.0.1/tcp/4001"},
		CreatedAt:    createdAt,
		ExpiresAt:    expiresAt,
		Signature:    make([]byte, 3309),
		KeyAlgorithm: identity.KeyAlgMLDSA65,
	}
}

// R5-001: Verify MUST accept an unexpired record whose lifetime
// (ExpiresAt - CreatedAt) exceeds 30 days. Per RFC-0003 §8.4 (Rev 5),
// the 30-day limit is a warning, not a verification rejection.
func TestR5_001_VerifyAcceptsOver30DayLifetimeUnexpiredRecord(t *testing.T) {
	now := uint64(1735689600) // 2025-01-01
	// Lifetime = 60 days, well over the 30-day advisory, but unexpired.
	record := makeRecord(t, now, now+60*86400)

	err := record.Verify(now, alwaysTrueVerifyFn)
	if err != nil {
		t.Fatalf("Verify must accept unexpired record with >30-day lifetime "+
			"per RFC-0003 §8.4 (Rev 5): %v", err)
	}
}

// R5-002: ExceedsMaxExpiryWarning(now) MUST return true when
// ExpiresAt - now > 30 days (2,592,000 seconds).
func TestR5_002_WarningTrueWhenExceeds30DaysFromNow(t *testing.T) {
	now := uint64(1735689600)
	record := makeRecord(t, now, now+identity.MaxRecordExpiry+1) // 30d + 1s

	if !record.ExceedsMaxExpiryWarning(now) {
		t.Fatal("warning must fire when ExpiresAt - now > 30 days")
	}
}

// R5-003: ExceedsMaxExpiryWarning(now) MUST return false when
// ExpiresAt - now <= 30 days (boundary inclusive).
func TestR5_003_WarningFalseWhenWithin30DaysFromNow(t *testing.T) {
	now := uint64(1735689600)

	// Exactly 30 days: boundary, not exceeding
	record := makeRecord(t, now, now+identity.MaxRecordExpiry)
	if record.ExceedsMaxExpiryWarning(now) {
		t.Fatal("warning must NOT fire at exactly 30 days (boundary)")
	}

	// 7 days: well within
	record = makeRecord(t, now, now+7*86400)
	if record.ExceedsMaxExpiryWarning(now) {
		t.Fatal("warning must NOT fire for 7-day record")
	}
}

// R5-004: ExceedsMaxExpiryWarning(now) MUST return false for an
// already-expired record (ExpiresAt <= now). The warning is about
// future lifetime, not past records.
func TestR5_004_WarningFalseForAlreadyExpiredRecord(t *testing.T) {
	now := uint64(1735689600)
	// Record that expired 1 second ago
	record := makeRecord(t, now-86400, now-1)

	if record.ExceedsMaxExpiryWarning(now) {
		t.Fatal("warning must NOT fire for an already-expired record")
	}
}
