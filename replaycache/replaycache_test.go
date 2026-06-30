package replaycache

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func agentID(seed byte) []byte {
	return makeBytes(AgentIDSize, seed)
}

func nonce(seed byte) []byte {
	return makeBytes(NonceSize, seed)
}

func makeBytes(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = seed
	}
	return b
}

// ── Basic functionality ────────────────────────────────────────────

func TestNewCacheIsEmpty(t *testing.T) {
	c := New()
	if !c.IsEmpty() {
		t.Fatal("new cache should be empty")
	}
	if c.Len() != 0 {
		t.Fatalf("Len: got %d, want 0", c.Len())
	}
	if c.Retention() != DefaultRetention {
		t.Fatalf("Retention: got %v, want %v", c.Retention(), DefaultRetention)
	}
	if c.MaxEntries() != DefaultMaxEntries {
		t.Fatalf("MaxEntries: got %d, want %d", c.MaxEntries(), DefaultMaxEntries)
	}
}

func TestCheckAndInsertFreshNonce(t *testing.T) {
	c := New()
	aid := agentID(1)
	n := nonce(0x42)
	if c.Check(aid, n) {
		t.Fatal("fresh nonce should not be replay")
	}
	if err := c.CheckAndInsert(aid, n); err != nil {
		t.Fatalf("first insert should succeed: %v", err)
	}
	if c.Len() != 1 {
		t.Fatalf("Len: got %d, want 1", c.Len())
	}
}

func TestCheckAndInsertReplayDetected(t *testing.T) {
	c := New()
	aid := agentID(1)
	n := nonce(0x42)
	if err := c.CheckAndInsert(aid, n); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	err := c.CheckAndInsert(aid, n)
	if err == nil {
		t.Fatal("second insert should be replay")
	}
	if !errors.Is(err, ErrNonceReuse) {
		t.Fatalf("expected ErrNonceReuse, got %v", err)
	}
	if c.Len() != 1 {
		t.Fatalf("replay should not add new entry, Len: %d", c.Len())
	}
}

func TestCheckDetectsExisting(t *testing.T) {
	c := New()
	aid := agentID(1)
	n := nonce(0x42)
	if err := c.CheckAndInsert(aid, n); err != nil {
		t.Fatal(err)
	}
	if !c.Check(aid, n) {
		t.Fatal("check should detect existing nonce")
	}
}

func TestCheckDoesNotDetectMissing(t *testing.T) {
	c := New()
	aid := agentID(1)
	n := nonce(0x42)
	if c.Check(aid, n) {
		t.Fatal("check should not detect missing nonce")
	}
}

func TestDifferentAgentSameNonceNotReplay(t *testing.T) {
	c := New()
	aid1 := agentID(1)
	aid2 := agentID(2)
	n := nonce(0x42)
	if err := c.CheckAndInsert(aid1, n); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckAndInsert(aid2, n); err != nil {
		t.Fatalf("same nonce, different agent should not be replay: %v", err)
	}
	if c.Len() != 2 {
		t.Fatalf("Len: got %d, want 2", c.Len())
	}
}

func TestDifferentNonceSameAgentNotReplay(t *testing.T) {
	c := New()
	aid := agentID(1)
	n1 := nonce(0x01)
	n2 := nonce(0x02)
	if err := c.CheckAndInsert(aid, n1); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckAndInsert(aid, n2); err != nil {
		t.Fatalf("same agent, different nonce should not be replay: %v", err)
	}
	if c.Len() != 2 {
		t.Fatalf("Len: got %d, want 2", c.Len())
	}
}

// ── Insert without check ───────────────────────────────────────────

func TestInsertWithoutCheck(t *testing.T) {
	c := New()
	aid := agentID(1)
	n := nonce(0x42)
	c.Insert(aid, n)
	if c.Len() != 1 {
		t.Fatalf("Len: got %d, want 1", c.Len())
	}
	if !c.Check(aid, n) {
		t.Fatal("inserted nonce should be detected by check")
	}
}

func TestInsertIdempotent(t *testing.T) {
	c := New()
	aid := agentID(1)
	n := nonce(0x42)
	c.Insert(aid, n)
	c.Insert(aid, n)
	if c.Len() != 1 {
		t.Fatalf("double insert should not duplicate, Len: %d", c.Len())
	}
}

// ── Eviction ───────────────────────────────────────────────────────

func TestEvictExpiredRemovesExpiredEntries(t *testing.T) {
	c := NewWithParamsUnchecked(50*time.Millisecond, 10000)
	aid := agentID(1)
	n := nonce(0x42)
	if err := c.CheckAndInsert(aid, n); err != nil {
		t.Fatal(err)
	}
	if c.Len() != 1 {
		t.Fatalf("Len: got %d, want 1", c.Len())
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

func TestExpiredNonceNotDetectedAsReplay(t *testing.T) {
	c := NewWithParamsUnchecked(50*time.Millisecond, 10000)
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

func TestExpiredNonceCheckReturnsFalse(t *testing.T) {
	c := NewWithParamsUnchecked(50*time.Millisecond, 10000)
	aid := agentID(1)
	n := nonce(0x42)
	if err := c.CheckAndInsert(aid, n); err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	if c.Check(aid, n) {
		t.Fatal("expired nonce should not be detected")
	}
}

func TestMaxEntriesEnforced(t *testing.T) {
	c := NewWithParamsUnchecked(60*time.Second, 5)
	for i := byte(0); i < 10; i++ {
		aid := agentID(i)
		n := nonce(i)
		if err := c.CheckAndInsert(aid, n); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	if c.Len() != 5 {
		t.Fatalf("cache should be capped at maxEntries, Len: %d", c.Len())
	}
}

func TestLRUEvictionAllowsReplayOfEvicted(t *testing.T) {
	c := NewWithParamsUnchecked(60*time.Second, 3)
	// Insert 3 entries.
	for i := byte(0); i < 3; i++ {
		aid := agentID(i)
		n := nonce(i)
		if err := c.CheckAndInsert(aid, n); err != nil {
			t.Fatal(err)
		}
	}
	if c.Len() != 3 {
		t.Fatalf("Len: got %d, want 3", c.Len())
	}
	// Insert 4th: should evict LRU (agent 0).
	aid3 := agentID(3)
	n3 := nonce(3)
	if err := c.CheckAndInsert(aid3, n3); err != nil {
		t.Fatal(err)
	}
	if c.Len() != 3 {
		t.Fatalf("Len: got %d, want 3", c.Len())
	}
	// Agent 0's nonce was evicted, so it should be insertable again.
	aid0 := agentID(0)
	n0 := nonce(0)
	if err := c.CheckAndInsert(aid0, n0); err != nil {
		t.Fatalf("evicted nonce should be insertable again: %v", err)
	}
}

// ── Parameter validation ───────────────────────────────────────────

func TestRetentionTooShort(t *testing.T) {
	_, err := NewWithParams(30*time.Second, 1000)
	if err == nil {
		t.Fatal("should fail for retention too short")
	}
}

func TestRetentionTooLong(t *testing.T) {
	_, err := NewWithParams(7200*time.Second, 1000)
	if err == nil {
		t.Fatal("should fail for retention too long")
	}
}

func TestMaxEntriesTooSmall(t *testing.T) {
	_, err := NewWithParams(300*time.Second, 100)
	if err == nil {
		t.Fatal("should fail for maxEntries too small")
	}
}

func TestMaxEntriesTooLarge(t *testing.T) {
	_, err := NewWithParams(300*time.Second, 20_000_000)
	if err == nil {
		t.Fatal("should fail for maxEntries too large")
	}
}

func TestValidParams(t *testing.T) {
	c, err := NewWithParams(120*time.Second, 5000)
	if err != nil {
		t.Fatalf("valid params should succeed: %v", err)
	}
	if c.Retention() != 120*time.Second {
		t.Fatalf("Retention: got %v, want 120s", c.Retention())
	}
	if c.MaxEntries() != 5000 {
		t.Fatalf("MaxEntries: got %d, want 5000", c.MaxEntries())
	}
}

// ── Clear ──────────────────────────────────────────────────────────

func TestClear(t *testing.T) {
	c := New()
	for i := byte(0); i < 10; i++ {
		aid := agentID(i)
		n := nonce(i)
		if err := c.CheckAndInsert(aid, n); err != nil {
			t.Fatal(err)
		}
	}
	if c.Len() != 10 {
		t.Fatalf("Len: got %d, want 10", c.Len())
	}
	c.Clear()
	if c.Len() != 0 {
		t.Fatalf("Len after clear: got %d, want 0", c.Len())
	}
}

// ── Concurrency ────────────────────────────────────────────────────

func TestConcurrentCheckAndInsert(t *testing.T) {
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
	errCount := 0
	for _, r := range results {
		if r == nil {
			okCount++
		} else {
			errCount++
		}
	}
	if okCount != 1 {
		t.Fatalf("exactly one concurrent insert should succeed, got %d", okCount)
	}
	if errCount != 9 {
		t.Fatalf("all others should be replay, got %d", errCount)
	}
}

func TestConcurrentDifferentNonces(t *testing.T) {
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
		t.Fatalf("all unique nonces should succeed, Len: %d", c.Len())
	}
}

// ── Edge cases ─────────────────────────────────────────────────────

func TestShortAgentIDPadded(t *testing.T) {
	c := New()
	aid := makeBytes(16, 0xAA) // Short agent ID (16 bytes)
	n := nonce(0x42)
	if err := c.CheckAndInsert(aid, n); err != nil {
		t.Fatal(err)
	}
	if !c.Check(aid, n) {
		t.Fatal("short agent ID should work")
	}
}

func TestAllZeroNonce(t *testing.T) {
	c := New()
	aid := agentID(1)
	n := makeBytes(NonceSize, 0)
	if err := c.CheckAndInsert(aid, n); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckAndInsert(aid, n); err == nil {
		t.Fatal("all-zero nonce replay should be detected")
	}
}

func TestAllFFNonce(t *testing.T) {
	c := New()
	aid := agentID(1)
	n := makeBytes(NonceSize, 0xFF)
	if err := c.CheckAndInsert(aid, n); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckAndInsert(aid, n); err == nil {
		t.Fatal("all-FF nonce replay should be detected")
	}
}

func TestManyNoncesSameAgent(t *testing.T) {
	c := New()
	aid := agentID(1)
	for i := byte(0); i < 100; i++ {
		n := nonce(i)
		if err := c.CheckAndInsert(aid, n); err != nil {
			t.Fatalf("nonce %d should be fresh: %v", i, err)
		}
	}
	if c.Len() != 100 {
		t.Fatalf("Len: got %d, want 100", c.Len())
	}
	for i := byte(0); i < 100; i++ {
		n := nonce(i)
		if !c.Check(aid, n) {
			t.Fatalf("nonce %d should be replay", i)
		}
	}
}

func TestManyAgentsSameNonce(t *testing.T) {
	c := New()
	n := nonce(0x42)
	for i := byte(0); i < 100; i++ {
		aid := agentID(i)
		if err := c.CheckAndInsert(aid, n); err != nil {
			t.Fatalf("agent %d should be fresh: %v", i, err)
		}
	}
	if c.Len() != 100 {
		t.Fatalf("Len: got %d, want 100", c.Len())
	}
}

func TestWithCapacity(t *testing.T) {
	c, err := NewWithCapacity(300*time.Second, 10000, 500)
	if err != nil {
		t.Fatal(err)
	}
	if c.MaxEntries() != 10000 {
		t.Fatalf("MaxEntries: got %d, want 10000", c.MaxEntries())
	}
}

func TestWrongNonceSize(t *testing.T) {
	c := New()
	aid := agentID(1)
	n := makeBytes(16, 0x42) // Wrong size
	if err := c.CheckAndInsert(aid, n); err == nil {
		t.Fatal("wrong nonce size should return error")
	}
}

func TestCheckWrongNonceSize(t *testing.T) {
	c := New()
	aid := agentID(1)
	n := makeBytes(16, 0x42) // Wrong size
	if c.Check(aid, n) {
		t.Fatal("wrong nonce size should return false")
	}
}
