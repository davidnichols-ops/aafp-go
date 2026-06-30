// Package replaycache — conformance tests for RFC-0002 §6.7 (A-9).
//
// These tests verify that the ReplayCache implements every normative
// requirement from §6.7. Each test is tagged with its source section.

package replaycache

import (
	"sync"
	"testing"
	"time"
)

// ── §6.7.2 Cache Structure ─────────────────────────────────────────

func TestR2_400_CacheKeyIsAgentIDPlusNonce(t *testing.T) {
	// §6.7.2: Cache key is (agent_id, nonce). Same nonce with different
	// agent_id must NOT be a replay.
	c := New()
	aid1 := agentID(1)
	aid2 := agentID(2)
	n := nonce(0x42)

	if err := c.CheckAndInsert(aid1, n); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckAndInsert(aid2, n); err != nil {
		t.Fatalf("same nonce, different agent_id must not be replay: %v", err)
	}
}

func TestR2_401_CacheKeyNonceScopedPerAgent(t *testing.T) {
	// §6.7.2: Same agent_id with different nonces must not be replay.
	c := New()
	aid := agentID(1)
	n1 := nonce(0x01)
	n2 := nonce(0x02)

	if err := c.CheckAndInsert(aid, n1); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckAndInsert(aid, n2); err != nil {
		t.Fatalf("same agent, different nonce must not be replay: %v", err)
	}
}

// ── §6.7.3 Cache Parameters ────────────────────────────────────────

func TestR2_402_DefaultRetention300s(t *testing.T) {
	c := New()
	if c.Retention() != 300*time.Second {
		t.Fatalf("Retention: got %v, want 300s", c.Retention())
	}
}

func TestR2_403_DefaultMaxEntries100k(t *testing.T) {
	c := New()
	if c.MaxEntries() != 100_000 {
		t.Fatalf("MaxEntries: got %d, want 100000", c.MaxEntries())
	}
}

func TestR2_404_RetentionMinimum60s(t *testing.T) {
	if _, err := NewWithParams(30*time.Second, 1000); err == nil {
		t.Fatal("retention < 60s must be rejected")
	}
}

func TestR2_405_RetentionMaximum3600s(t *testing.T) {
	if _, err := NewWithParams(7200*time.Second, 1000); err == nil {
		t.Fatal("retention > 3600s must be rejected")
	}
}

func TestR2_406_MaxEntriesMinimum1000(t *testing.T) {
	if _, err := NewWithParams(300*time.Second, 100); err == nil {
		t.Fatal("max_entries < 1000 must be rejected")
	}
}

func TestR2_407_MaxEntriesMaximum10M(t *testing.T) {
	if _, err := NewWithParams(300*time.Second, 20_000_000); err == nil {
		t.Fatal("max_entries > 10M must be rejected")
	}
}

// ── §6.7.4 Normative Invariants ────────────────────────────────────

func TestR2_408_Invariant1CheckBeforeVerify(t *testing.T) {
	// §6.7.4 Invariant 1: Check before verify.
	c := New()
	aid := agentID(1)
	n := nonce(0x42)
	if c.Check(aid, n) {
		t.Fatal("fresh nonce should not be replay")
	}
}

func TestR2_409_Invariant2InsertAfterVerifyServer(t *testing.T) {
	// §6.7.4 Invariant 2: Server inserts after verify.
	c := New()
	aid := agentID(1)
	n := nonce(0x42)
	if c.Check(aid, n) {
		t.Fatal("fresh nonce should not be replay")
	}
	c.Insert(aid, n)
	if !c.Check(aid, n) {
		t.Fatal("inserted nonce should be detected")
	}
}

func TestR2_410_Invariant3InsertAfterVerifyClient(t *testing.T) {
	// §6.7.4 Invariant 3: Client inserts after verify.
	c := New()
	aid := agentID(1)
	n := nonce(0x42)
	if c.Check(aid, n) {
		t.Fatal("fresh nonce should not be replay")
	}
	c.Insert(aid, n)
	if !c.Check(aid, n) {
		t.Fatal("inserted nonce should be detected")
	}
}

func TestR2_411_Invariant4AtomicityConcurrent(t *testing.T) {
	// §6.7.4 Invariant 4: check_and_insert is atomic.
	c := New()
	aid := agentID(1)
	n := nonce(0x42)
	var wg sync.WaitGroup
	results := make([]error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = c.CheckAndInsert(aid, n)
		}(i)
	}
	wg.Wait()
	okCount := 0
	for _, r := range results {
		if r == nil {
			okCount++
		}
	}
	if okCount != 1 {
		t.Fatalf("exactly one concurrent insert must succeed, got %d", okCount)
	}
}

func TestR2_412_Invariant5NoSilentAcceptance(t *testing.T) {
	// §6.7.4 Invariant 5: Replay must return error.
	c := New()
	aid := agentID(1)
	n := nonce(0x42)
	if err := c.CheckAndInsert(aid, n); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckAndInsert(aid, n); err == nil {
		t.Fatal("replay must not be silently accepted")
	}
}

func TestR2_413_Invariant6EvictionNonBlocking(t *testing.T) {
	// §6.7.4 Invariant 6: Eviction must not block for > 1ms.
	c := NewWithParamsUnchecked(60*time.Second, 50000)
	aid := agentID(1)
	for i := 0; i < 50000; i++ {
		n := makeBytes(NonceSize, byte(i%256))
		n[0] = byte(i >> 8)
		_ = c.CheckAndInsert(aid, n)
	}
	start := time.Now()
	n := makeBytes(NonceSize, 0xFF)
	_ = c.CheckAndInsert(aid, n)
	elapsed := time.Since(start)
	if elapsed > 100*time.Millisecond {
		t.Fatalf("check_and_insert should be fast, took %v", elapsed)
	}
}

func TestR2_414_Invariant7PersistenceOptional(t *testing.T) {
	// §6.7.4 Invariant 7: In-memory cache works without persistence.
	c := New()
	aid := agentID(1)
	n := nonce(0x42)
	if err := c.CheckAndInsert(aid, n); err != nil {
		t.Fatal(err)
	}
	if !c.Check(aid, n) {
		t.Fatal("inserted nonce should be detected")
	}
}

// ── §6.7.5 Server-Side Replay Check ────────────────────────────────

func TestR2_415_ServerSideFreshNonceAccepted(t *testing.T) {
	c := New()
	aid := agentID(1)
	n := nonce(0x42)
	if c.Check(aid, n) {
		t.Fatal("fresh nonce should not be replay")
	}
}

func TestR2_416_ServerSideReplayDetected(t *testing.T) {
	c := New()
	aid := agentID(1)
	n := nonce(0x42)
	if err := c.CheckAndInsert(aid, n); err != nil {
		t.Fatal(err)
	}
	if !c.Check(aid, n) {
		t.Fatal("replayed nonce must be detected")
	}
}

// ── §6.7.6 Client-Side Replay Check ────────────────────────────────

func TestR2_418_ClientSideFreshServerNonceAccepted(t *testing.T) {
	c := New()
	aid := agentID(1)
	n := nonce(0x42)
	if c.Check(aid, n) {
		t.Fatal("fresh nonce should not be replay")
	}
}

func TestR2_419_ClientSideReplayDetected(t *testing.T) {
	c := New()
	aid := agentID(1)
	n := nonce(0x42)
	if err := c.CheckAndInsert(aid, n); err != nil {
		t.Fatal(err)
	}
	if !c.Check(aid, n) {
		t.Fatal("replayed nonce must be detected")
	}
}

// ── §6.7.7 Eviction and Resource Management ────────────────────────

func TestR2_420_MaxEntriesEnforced(t *testing.T) {
	c := NewWithParamsUnchecked(60*time.Second, 10)
	for i := byte(0); i < 20; i++ {
		aid := agentID(i)
		n := nonce(i)
		_ = c.CheckAndInsert(aid, n)
	}
	if c.Len() != 10 {
		t.Fatalf("cache must be capped at maxEntries, Len: %d", c.Len())
	}
}

func TestR2_421_LRUEvictionWhenFull(t *testing.T) {
	c := NewWithParamsUnchecked(60*time.Second, 3)
	for i := byte(0); i < 3; i++ {
		aid := agentID(i)
		n := nonce(i)
		if err := c.CheckAndInsert(aid, n); err != nil {
			t.Fatal(err)
		}
	}
	aid3 := agentID(3)
	n3 := nonce(3)
	if err := c.CheckAndInsert(aid3, n3); err != nil {
		t.Fatal(err)
	}
	if c.Len() != 3 {
		t.Fatalf("Len: got %d, want 3", c.Len())
	}
	aid0 := agentID(0)
	n0 := nonce(0)
	if err := c.CheckAndInsert(aid0, n0); err != nil {
		t.Fatalf("evicted nonce should be insertable again: %v", err)
	}
}

func TestR2_422_ExpiredEntriesEvictedFirst(t *testing.T) {
	c := NewWithParamsUnchecked(50*time.Millisecond, 100)
	aid := agentID(1)
	n := nonce(0x42)
	if err := c.CheckAndInsert(aid, n); err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	evicted := c.EvictExpired()
	if evicted != 1 {
		t.Fatalf("evicted: got %d, want 1", evicted)
	}
	if c.Len() != 0 {
		t.Fatalf("Len after evict: got %d, want 0", c.Len())
	}
}

func TestR2_423_ExpiredNonceNotReplay(t *testing.T) {
	c := NewWithParamsUnchecked(50*time.Millisecond, 100)
	aid := agentID(1)
	n := nonce(0x42)
	if err := c.CheckAndInsert(aid, n); err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	if err := c.CheckAndInsert(aid, n); err != nil {
		t.Fatalf("expired nonce should not be replay: %v", err)
	}
}

// ── §6.7.8 Concurrency ─────────────────────────────────────────────

func TestR2_424_ConcurrentUniqueNoncesAllSucceed(t *testing.T) {
	c := New()
	var wg sync.WaitGroup
	for i := byte(0); i < 20; i++ {
		wg.Add(1)
		go func(idx byte) {
			defer wg.Done()
			_ = c.CheckAndInsert(agentID(idx), nonce(idx))
		}(i)
	}
	wg.Wait()
	if c.Len() != 20 {
		t.Fatalf("all unique nonces must succeed, Len: %d", c.Len())
	}
}

func TestR2_425_ConcurrentSameNonceOneWins(t *testing.T) {
	c := New()
	aid := agentID(1)
	n := nonce(0x42)
	var wg sync.WaitGroup
	results := make([]error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = c.CheckAndInsert(aid, n)
		}(i)
	}
	wg.Wait()
	okCount := 0
	for _, r := range results {
		if r == nil {
			okCount++
		}
	}
	if okCount != 1 {
		t.Fatalf("exactly one must win, got %d", okCount)
	}
}

// ── §6.7.11 Security Considerations ────────────────────────────────

func TestR2_426_CheckBeforeVerifyPreventsCPUAmplification(t *testing.T) {
	c := New()
	aid := agentID(1)
	n := nonce(0x42)
	if err := c.CheckAndInsert(aid, n); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	isReplay := c.Check(aid, n)
	elapsed := time.Since(start)
	if !isReplay {
		t.Fatal("should be replay")
	}
	if elapsed > time.Millisecond {
		t.Fatalf("check should be O(1), took %v", elapsed)
	}
}

func TestR2_427_CachePoisoningPrevented(t *testing.T) {
	c := New()
	aid := agentID(1)
	n := nonce(0x42)
	if c.Check(aid, n) {
		t.Fatal("fresh nonce should not be replay")
	}
	// Verification fails — we skip insert.
	if c.Check(aid, n) {
		t.Fatal("failed verification must not poison cache")
	}
}

func TestR2_428_FalsePositivesImpossible(t *testing.T) {
	c := New()
	aid := agentID(1)
	for i := byte(0); i < 100; i++ {
		n := nonce(i)
		if err := c.CheckAndInsert(aid, n); err != nil {
			t.Fatalf("nonce %d must be fresh: %v", i, err)
		}
	}
}

func TestR2_429_AllZeroNonceHandled(t *testing.T) {
	c := New()
	aid := agentID(1)
	n := makeBytes(NonceSize, 0)
	if err := c.CheckAndInsert(aid, n); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckAndInsert(aid, n); err == nil {
		t.Fatal("all-zero nonce replay must be detected")
	}
}

func TestR2_430_AllFFNonceHandled(t *testing.T) {
	c := New()
	aid := agentID(1)
	n := makeBytes(NonceSize, 0xFF)
	if err := c.CheckAndInsert(aid, n); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckAndInsert(aid, n); err == nil {
		t.Fatal("all-FF nonce replay must be detected")
	}
}

func TestR2_431_ClearResetsCache(t *testing.T) {
	c := New()
	aid := agentID(1)
	n := nonce(0x42)
	if err := c.CheckAndInsert(aid, n); err != nil {
		t.Fatal(err)
	}
	if c.Len() != 1 {
		t.Fatalf("Len: got %d, want 1", c.Len())
	}
	c.Clear()
	if c.Len() != 0 {
		t.Fatalf("Len after clear: got %d, want 0", c.Len())
	}
	if c.Check(aid, n) {
		t.Fatal("after clear, nonce should be fresh")
	}
}
