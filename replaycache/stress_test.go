// Package replaycache — stress tests for RFC-0002 §6.7 (A-9).

package replaycache

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func makeNonceStress(seed uint32) []byte {
	n := make([]byte, NonceSize)
	n[0] = byte(seed >> 24)
	n[1] = byte(seed >> 16)
	n[2] = byte(seed >> 8)
	n[3] = byte(seed)
	return n
}

// ── 100K nonces ────────────────────────────────────────────────────

func TestStress100KNoncesSingleAgent(t *testing.T) {
	c := New()
	aid := agentID(1)
	count := uint32(100_000)

	start := time.Now()
	for i := uint32(0); i < count; i++ {
		n := makeNonceStress(i)
		if err := c.CheckAndInsert(aid, n); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	insertElapsed := time.Since(start)
	if c.Len() != int(count) {
		t.Fatalf("Len: got %d, want %d", c.Len(), count)
	}

	start = time.Now()
	for i := uint32(0); i < count; i++ {
		n := makeNonceStress(i)
		if !c.Check(aid, n) {
			t.Fatalf("nonce %d should be replay", i)
		}
	}
	checkElapsed := time.Since(start)

	if insertElapsed > 5*time.Second {
		t.Fatalf("100K inserts took %v", insertElapsed)
	}
	if checkElapsed > 5*time.Second {
		t.Fatalf("100K checks took %v", checkElapsed)
	}
}

func TestStress100KNoncesDifferentAgents(t *testing.T) {
	c := New()
	count := uint32(100_000)

	start := time.Now()
	for i := uint32(0); i < count; i++ {
		aid := agentID(byte(i % 256))
		n := makeNonceStress(i)
		if err := c.CheckAndInsert(aid, n); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	elapsed := time.Since(start)
	if c.Len() != int(count) {
		t.Fatalf("Len: got %d, want %d", c.Len(), count)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("100K inserts (different agents) took %v", elapsed)
	}
}

// ── Concurrency stress ─────────────────────────────────────────────

func TestStressConcurrent10KNonces10Threads(t *testing.T) {
	c := New()
	threads := 10
	perThread := uint32(10_000)
	var wg sync.WaitGroup

	start := time.Now()
	for tid := 0; tid < threads; tid++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			aid := agentID(byte(id))
			for i := uint32(0); i < perThread; i++ {
				n := makeNonceStress(uint32(id)*perThread + i)
				if err := c.CheckAndInsert(aid, n); err != nil {
					t.Errorf("insert: %v", err)
				}
			}
		}(tid)
	}
	wg.Wait()
	elapsed := time.Since(start)

	if c.Len() != threads*int(perThread) {
		t.Fatalf("Len: got %d, want %d", c.Len(), threads*int(perThread))
	}
	if elapsed > 10*time.Second {
		t.Fatalf("concurrent 100K inserts took %v", elapsed)
	}
}

func TestStressConcurrentSameNonce100Threads(t *testing.T) {
	c := New()
	aid := agentID(1)
	n := nonce(0x42)
	threads := 100
	var wg sync.WaitGroup
	results := make([]error, threads)

	for i := 0; i < threads; i++ {
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
		t.Fatalf("exactly one must win out of %d threads, got %d", threads, okCount)
	}
	if c.Len() != 1 {
		t.Fatalf("Len: got %d, want 1", c.Len())
	}
}

// ── Eviction stress ────────────────────────────────────────────────

func TestStressEvictionWithSmallMaxEntries(t *testing.T) {
	c := NewWithParamsUnchecked(60*time.Second, 1000)
	aid := agentID(1)
	for i := uint32(0); i < 100_000; i++ {
		n := makeNonceStress(i)
		if err := c.CheckAndInsert(aid, n); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	if c.Len() != 1000 {
		t.Fatalf("cache must stay at maxEntries, Len: %d", c.Len())
	}
}

func TestStressEvictionAllowsReplayOfEvicted(t *testing.T) {
	c := NewWithParamsUnchecked(60*time.Second, 100)
	aid := agentID(1)
	for i := uint32(0); i < 200; i++ {
		n := makeNonceStress(i)
		if err := c.CheckAndInsert(aid, n); err != nil {
			t.Fatal(err)
		}
	}
	if c.Len() != 100 {
		t.Fatalf("Len: got %d, want 100", c.Len())
	}
	n0 := makeNonceStress(0)
	if err := c.CheckAndInsert(aid, n0); err != nil {
		t.Fatalf("evicted nonce should be insertable again: %v", err)
	}
}

// ── Memory bounds ──────────────────────────────────────────────────

func TestStressMemoryBoundedAtMaxEntries(t *testing.T) {
	max := 10_000
	c := NewWithParamsUnchecked(60*time.Second, max)
	aid := agentID(1)
	for i := uint32(0); i < uint32(max*5); i++ {
		n := makeNonceStress(i)
		if err := c.CheckAndInsert(aid, n); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	if c.Len() != max {
		t.Fatalf("cache must not exceed max_entries, Len: %d", c.Len())
	}
}

// ── Expiry stress ──────────────────────────────────────────────────

func TestStressExpiredEntriesCleanedUp(t *testing.T) {
	c := NewWithParamsUnchecked(50*time.Millisecond, 10_000)
	aid := agentID(1)
	for i := uint32(0); i < 1000; i++ {
		n := makeNonceStress(i)
		if err := c.CheckAndInsert(aid, n); err != nil {
			t.Fatal(err)
		}
	}
	if c.Len() != 1000 {
		t.Fatalf("Len: got %d, want 1000", c.Len())
	}
	time.Sleep(60 * time.Millisecond)
	evicted := c.EvictExpired()
	if evicted != 1000 {
		t.Fatalf("evicted: got %d, want 1000", evicted)
	}
	if c.Len() != 0 {
		t.Fatalf("Len after evict: got %d, want 0", c.Len())
	}
	for i := uint32(0); i < 1000; i++ {
		n := makeNonceStress(i)
		if err := c.CheckAndInsert(aid, n); err != nil {
			t.Fatalf("expired nonce %d should be fresh: %v", i, err)
		}
	}
}

// ── Mixed workload ─────────────────────────────────────────────────

func TestStressMixedInsertAndCheck(t *testing.T) {
	c := New()
	aid := agentID(1)
	var wg sync.WaitGroup

	// Thread 1: insert nonces 0-4999
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := uint32(0); i < 5000; i++ {
			n := makeNonceStress(i)
			if err := c.CheckAndInsert(aid, n); err != nil {
				t.Errorf("insert: %v", err)
			}
		}
	}()

	// Thread 2: insert nonces 5000-9999
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := uint32(5000); i < 10000; i++ {
			n := makeNonceStress(i)
			if err := c.CheckAndInsert(aid, n); err != nil {
				t.Errorf("insert: %v", err)
			}
		}
	}()

	// Thread 3: check nonces 0-9999
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := uint32(0); i < 10000; i++ {
			n := makeNonceStress(i)
			_ = c.Check(aid, n)
		}
	}()

	wg.Wait()
	if c.Len() != 10_000 {
		t.Fatalf("Len: got %d, want 10000", c.Len())
	}
}

// Ensure fmt is used
var _ = fmt.Sprintf
